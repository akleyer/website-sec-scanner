# SSL Scan Service

## Description
This Python script utilizes the SSL Labs API to perform comprehensive SSL scans on specified domains, assessing their security and certificate validity. It's designed to be easily deployable in a containerized environment using Docker, facilitating scalability and ease of use.

## Installation and Running the Script

### Prerequisites
- Docker
- Python 3.x (if running locally)
- Pip (if running locally)

### Building the Docker Image
```bash
docker build -t ssl-scan .
```

### Running the Docker Container
Replace www.example.com with the domain you wish to scan.

```bash
docker run ssl-scan www.example.com
```

This starts a new scan, to run a scan on a cached report, specify the `--use_cache` flag

```bash
docker run ssl-scan www.example.com --use_cache
```

Lastly, to properly format the output for email, use the `--email_format` flag

```bash
docker run ssl-scan www.example.com --use_cache --email_format
```

## Scaling and Resilience
While there are multiple ways to scale this service to handle thousands of domains, updating the Python script to process multiple domains in a single execution is the most efficient approach. This method reduces overhead, simplifies deployment, and improves resource utilization.

### Alternative scaling methods include:

- **Parallel Docker Containers:** Running separate containers for each domain scan. This method increases overhead and complexity.
- **Kubernetes Deployment:** For horizontal scaling, distributing the domain list across multiple service instances managed by Kubernetes.

## Monitoring and Alerting
For effective monitoring and alerting, focus on key metrics such as SSL security grades, certificate issues, and expiration timelines. Specifically, monitor for:

- **SSL Security Grade Changes**: Alert on any changes to the SSL security grade of domains to quickly address potential security downgrades.
- **Certificate Issues**: Monitor for any flagged issues within certificates that could impact domain trustworthiness.
- **Certificate Expiry**: Track certificates nearing expiry or already expired, as these pose significant security risks and could lead to service disruptions.

**Alerting**: Configure alerts to be sent to a designated Slack channel, ensuring real-time notification and swift response to any of the above events. This enables a proactive approach to maintaining SSL security standards across all monitored domains.

## Handling New Domains and Certificate Expiry
Develop an API for dynamically adding domains to the scan queue. Implement scheduled scans to monitor certificate expiries, alerting administrators via integrated notification systems as certificates approach their expiry dates.

## Managing Continuous Requirement Changes
Adopt Agile methodologies for iterative development and fast feedback cycles. Utilize CI/CD pipelines for automated testing and deployment, ensuring that the service remains up-to-date with the latest security standards and feature requests.
