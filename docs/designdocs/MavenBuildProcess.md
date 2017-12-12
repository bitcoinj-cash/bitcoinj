# Maven Build Process

* to run unit tests - `mvn clean test`
* to run unit tests & integration tests - `mvn clean verify`

Coverage reports are produced for bitcoincashj-core by the integration tests and are available 
at `core/target/site/jacoco/index.html`.

## Profiles
The default profile is the `dev` profile. This profile will exclude Integration tests that have
external dependencies (e.g. Postgresql, MySQL).

The `travis` profile is used for travis-ci.org. This profile will include all Integration tests.

## MySQL Integration Tests
To run the MySQL Integration tests locally, you will need a standard MySQL installation. The following SQL commands create a database and user account:
```
CREATE DATABASE bitcoinj_test;
GRANT ALL PRIVILEGES ON bitcoinj_test.* TO 'bitcoinj' IDENTIFIED BY 'password';
SET GLOBAL max_allowed_packet=20971520;
```

Notes:
* the maximum allowed packet size must be at least 20MB. The command above will set this properly until the next MySQL restart
* this is not a secure configuration, only expose the MySQL on localhost and delete the user and database when no longer needed

## PostgreSQL Integration Tests
To run the PostgreSQL integration tests locally, you will need a standard PostgreSQL installation, version 9.3 or higher. The following SQL commands
create a database and user account for the tests:
```
create user bitcoinj with password 'password';
create database bitcoinj_test owner bitcoinj;
```

Notes:
* this is not a secure configuration, only expose the PostgreSQL on localhost and delete the user and database when no longer needed

## Process Design Goals

* follow Maven philosophy & be as standard as possible
* devs can immediately get started with defaults
* separate unit and integration tests
* travis-ci.org support
* coveralls.io support

Unit tests must not have external dependencies and must be fast. Developers must be
able to execute these tests frequently without disrupting flow of work. Unit tests
which take too much time should be moved to the integration test set.

Integration tests are divided into a number of groups. Tests in the base group must 
have no external dependencies except disk, io, memory, network. Tests which have other
external dependencies (e.g. Postgres, MySQL) must be grouped according to the
dependency. By default, only the tests from the base group are performed. 
The tests from all groups must be performed by Travis. 

Coverage reports must be produced for bitcoincashj-core by the Integration tests. Travis must 
upload these to coveralls.io.
