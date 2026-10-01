# :link: Ligoj IAM Node based provider ![Maven Central](https://img.shields.io/maven-central/v/org.ligoj.plugin/plugin-iam-node)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=org.ligoj.plugin%3Aplugin-iam-node&metric=coverage)](https://sonarcloud.io/dashboard?id=org.ligoj.plugin%3Aplugin-iam-node)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?metric=alert_status&project=org.ligoj.plugin:plugin-iam-node)](https://sonarcloud.io/dashboard/index/org.ligoj.plugin:plugin-iam-node)
[![CodeFactor](https://www.codefactor.io/repository/github/ligoj/plugin-iam-node/badge)](https://www.codefactor.io/repository/github/ligoj/plugin-iam-node)
[![License](http://img.shields.io/:license-mit-blue.svg)](http://fabdouglas.mit-license.org/)

[Ligoj](https://github.com/ligoj/ligoj) A node based IAM provider

## Configuration

| Configuration | Description |
|---|---|
| `feature:iam:node:primary` | Identity node providing the users, groups and companies, e.g. `service:id:ldap:main`. Set at install time to the first `service:id` node, else to `empty`. |
| `feature:iam:node:secondary` | Comma separated identity nodes tried first for the authentication when they accept the login. |

When the primary node is undefined, `empty`, or does not resolve to an installed identity plug-in, the fail-safe empty
IAM is used: it accepts any login with any password and knows no user nor group. The administrators then see a warning
chip next to their name in the application bar (session warning `iam-node-no-primary` or `iam-node-primary-not-found`).
