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

async function performHttpChallengeWithRetry(domain, initialDelay = 0) {
    const maxRetries = 5;
    const delayInterval = 120000; // 2 minutes
    let lastError;

    // Sleep before starting the retry loop
    if (initialDelay > 0) {
        await new Promise(resolve => setTimeout(resolve, initialDelay));
    }

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            await performHttpChallenge(domain);
            return; // Success
        } catch (error) {
            lastError = error;
            if (attempt < maxRetries) {
                const delay = initialDelay * Math.pow(2, attempt);
                logger.warn(`HTTP challenge attempt ${attempt + 1} failed for ${domain}, retrying in ${delay}ms:`, error.message);
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                logger.error(`HTTP challenge failed for ${domain} after ${maxRetries + 1} attempts:`, lastError);
            }
        }
    }
}

const startSubscription = async () => {
    try {
        for await (let event of await tables.ChallengeCertificate.subscribe()) {
            try {
                const data = event.value?.data;
                if (!data) continue;
                if (!data.challengeToken) {
                    const { isLeader, totalNodes } = await isChallengeLeader();
                    if (isLeader) {
                        // Wait 60 seconds per additional node before starting the challenge for deployment
                        const initialDelay = (totalNodes - 1) * 60000;
                        // Fire and forget - don't block other events
                        performHttpChallengeWithRetry(data.domain, initialDelay);
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
    const interval = setInterval(async () => {
        for await (const challengeDomain of tables.ChallengeCertificate.search({
            conditions: [{attribute: 'renewalDate',  comparator: 'less_than', value: new Date()}]
        })){
            const { isLeader } = await isChallengeLeader();
            if (isLeader) {
                await performHttpChallenge(challengeDomain.domain, true);
            }
        }
    }, 43200000); // Every 12 hours

    interval.unref();
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

            // Wait for replication / restarts / component deployments (60 seconds)
            await new Promise((resolve) => setTimeout(resolve, 60000));

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
            renewalDate: renewalDate,
            challengeToken: null,
            challengeContent: null
        });

        console.log(`Certificate issued successfully for ${domain}`);
        await server.operation(
            {
                operation: 'add_certificate',
                name: `${domain}`,
                certificate:`${cert}`,
                is_authority: false,
                private_key: `${privateKey}`,
                replicated: true
            });

        return cert;

    } catch (error) {
        console.error(`Failed to issue certificate for ${domain}:`, error);
        throw error;
    }
}

async function isChallengeLeader() {
    let totalCount = 0;
    let isLeader = false;
    let firstNodeName = null;

    for await (const hdbNode of databases.system.table.hdb_nodes.search()) {
        totalCount++;

        // Store the first node's name to determine leadership
        if (totalCount === 1) {
            firstNodeName = hdbNode.name;
        }
    }

    // Only perform HTTP Challenge on one node. Use the first node in `hdb_nodes` to determine the challenge leader
    if (totalCount === 0) {
        // If no HDB nodes exist, perform HTTP Challenge Certificate Request
        isLeader = true;
    } else if (firstNodeName === replication.hostname) {
        // This node is the first node, so it's the leader
        isLeader = true;
    }

    return { isLeader, totalNodes: totalCount };
}