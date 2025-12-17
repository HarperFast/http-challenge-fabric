import * as acme from 'acme-client';

const { replication } = server.config;

server.http(async (request, next) => {
    if (request.url.startsWith('/.well-known/')) {
        const pathParts = request.url.split('/');
        if (pathParts.length !== 3) return next(request);

        for await (const challenge of tables.ChallengeCertificate.search({
            conditions: [{attribute: 'challengeToken', equal: pathParts[2]}]
        })) {
            if (challenge.challengeContent) {
                return {
                    status: 200,
                    headers: {},
                    body: challenge.challengeContent
                };
            }
        }
    }
    // otherwise, forward on through the middleware
    return next(request);
});

const startSubscription = async () => {
    try {
        for await (let event of await tables.ChallengeCertificate.subscribe()) {
            try {
                const data = event.value?.data;
                if (!data) continue;
                if (!data.challengeToken) {
                    if (await isChallengeLeader()) {
                        await performHttpChallenge(data.domain);
                    }
                }
            } catch (err) {
                // Log individual event processing errors but keep subscription alive
                logger.error('Error processing ChallengeCertificate event:', err);
            }
        }
    } catch (err) {
        // Subscription failed, log and restart
        logger.error('Challenge Certificate subscription crashed, restarting in 5 seconds:', err);
        setTimeout(startSubscription, 5000);
    }
};

// We only want this to trigger one time.
if (server.workerIndex === 0) {
    startSubscription();
    setInterval(async () => {
        for await (const challengeDomain of tables.ChallengeCertificate.search({
            conditions: [{attribute: 'renewalDate',  comparator: 'less_than', value: new Date()}]
        })){
            if (await isChallengeLeader()) {
                await performHttpChallenge(challengeDomain.domain, true);
            }
        }
    }, 43200000); // Every 12 hours
}

async function performHttpChallenge(domain, renewal = false) {
    try {
        // Create ACME client - using Let's Encrypt staging for testing
        // Change to acme.directory.letsencrypt.production for production
        const client = new acme.Client({
            directoryUrl: acme.directory.letsencrypt.staging,
            accountKey: await acme.crypto.createPrivateKey()
        });

        // Create Certificate Signing Request (CSR)
        const [privateKey, csr] = await acme.crypto.createCsr({
            commonName: domain
        });

        // Create certificate order
        const order = await client.createOrder({
            identifiers: [
                { type: 'dns', value: domain }
            ]
        });

        // Get authorizations and challenges
        const authorizations = await client.getAuthorizations(order);

        for (const authz of authorizations) {
            // Find HTTP-01 challenge
            const httpChallenge = authz.challenges.find(c => c.type === 'http-01');

            if (!httpChallenge) {
                throw new Error(`No HTTP-01 challenge available for ${domain}`);
            }

            // Get the key authorization (content to serve)
            const keyAuthorization = await client.getChallengeKeyAuthorization(httpChallenge);

            // Store challenge in database so WellKnown.js can serve it
            await tables.ChallengeCertificate.put({
                domain: domain,
                challengeToken: httpChallenge.token,
                challengeContent: keyAuthorization
            });

            // Wait for replication
            await new Promise((resolve) => setTimeout(resolve, 3000));

            // Notify Let's Encrypt that we're ready for validation
            await client.completeChallenge(httpChallenge);

            // Wait for validationll
            await client.waitForValidStatus(httpChallenge);
        }

        // Finalize the order by submitting the CSR
        await client.finalizeOrder(order, csr);

        let cert = null;
        if (renewal) {
            // For renewals, we need to get the updated order before getting the certificate to ensure the renewal is complete
            await client.waitForValidStatus(order);
            await new Promise((resolve) => setTimeout(resolve, 1000));
            const finalizedOrder = await client.getOrder(order);
            cert = await client.getCertificate(finalizedOrder);
        } else {
            cert = await client.getCertificate(order);
        }

        // Update the record with certificate issuance and renewal dates
        const now = new Date();
        const renewalDate = new Date(now);
        renewalDate.setDate(renewalDate.getDate() + 60); // Renew 30 days before 90-day expiry

        await tables.ChallengeCertificate.put({
            domain: domain,
            issueDate: now,
            renewalDate: renewalDate
        });

        console.log(`Certificate issued successfully for ${domain}`);
        await server.operation(
            {
                operation: 'add_certificate',
                name: `${domain}`,
                certificate:`${cert}`,
                is_authority: false,
                private_key: `${privateKey}`
            });

        return cert;

    } catch (error) {
        console.error(`Failed to issue certificate for ${domain}:`, error);
        throw error;
    }
}

async function isChallengeLeader() {
    let hdbNodesExist = false;
    for await (const hdbNode of databases.system.table.hdb_nodes.search()) {
        hdbNodesExist = true;
        // Only perform HTTP Challenge on one node. Use the order of `hdb_nodes` to determine a challenge leader
        if (hdbNode.name === replication.hostname) {
            // Perform HTTP Challenge Certificate Request
            return true
        }

        // Only check the first record because we only want to do this on one node in a cluster
        break;
    }

    // If no HDB nodes exist, perform HTTP Challenge Certificate Request
    return !hdbNodesExist;
}