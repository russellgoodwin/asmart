asmart v0.1
Russell Goodwin, Illumio Field CTO, 22-04-2024

asmart, or 'Attack Surface Mitigation And Reporting Tool' is a tool to review a current Illumio environment and identify various metrics around Workloads, activity and exposure.

The tool uses flow and workload data to identify a number of things
- What services are hosted and listening on a workload
- What is the associated risk of these services based on risk rating
- What potential exposure do these services have
- What actual use do these services have based on flow data
- How many peers workloads have, both in bound and outbound
- How many flows exist for these relationships, telling how active the services are and to/from where
- What mitigations could be applied to lock services down to just those peers that are active
- What the resultant mitigated risk score could be. Helping to prioritise services, workloads and applications to be secured.

In addition, there are extended capabilities for statistics based on metadata associations of these devices, enabling, where workloads are labelled

- Identify app peer relationships, relationships counts and flow counts
- Identify app group peer relationshiops, defined as above but with app/env label pairings
- Identify inter-environment flow patterns, to quantity traffic data flows traversing between environments

There are 3 components to the tool in the 0.1 release.

1) asprequests.py - a wrapper for the Illumio API that simplifies query to the API, Async API and the Async Traffic API.
2) asmart.py - The tool that collections data via the API and generates derivative data based on the workload and traffic data
3) asmart-report.py - The tool that exports the data and creates statistical analysis of this source data.

asprequests.py comes with a json configuration file that must be populated. This is where the FQDN for your PCE is entered, along with the org number for the instance to be analyzed and read only API credentials for the tool to make the API requests. The tool requires global read access and makes no changes to the environment.

asmart.conf is a json configuration file for the tool itself. Allowing variables  to be configured for the reporting. In this release, the only supported options are :

1) Protocol scores - where risk scores are configured for the in scope protocols.
2) devicecount - The number of workloads in the environment under analsysis. This metric is used to calculate exposure scores.
3) queryhours - This sets the delta time from current time for traffic data queries. 168 hours is the default, and looks at 7 days of data.