# JWT token mechanism: cob-token-library

A Java library for handling JWT (JSON Web Token) token generation, validation, and parsing, designed for secure authentication and authorization in Java applications.

## Features

- Generate JWT tokens with custom claims (e\.g\., username, role)
- Validate JWT tokens and check for expiration and issuer
- Extract token details such as role, issuer, and expiration
- Built\-in unit tests using JUnit and AssertJ
- Uses [jjwt](https://github.com/jwtk/jjwt) for JWT operations
- Lombok for boilerplate code reduction

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3\.6\+ 

### Installation

Add the following dependency to your Maven `pom\.xml`:

```xml
<dependency>
    <groupId>com.cob</groupId>
    <artifactId>cob-token-lib</artifactId>
    <version>1.1-SNAPSHOT</version>
</dependency>