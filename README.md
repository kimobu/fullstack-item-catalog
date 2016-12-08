# Swiss Pairings tournament
This repository implements the Udacity Full Stack Nanodegree project
requirements for the Relational Databases module. It provides
[Swiss pairings](https://en.wikipedia.org/wiki/Swiss-system_tournament)

# Usage
This project assumes a Postgres backend that is included with the Vagrant VM.

To setup vagrant:

`cd vagrant; vagrant up; vagrant ssh`

Note: MacOS users may need to follow the workaround for curl found [here](https://github.com/mitchellh/vagrant/issues/7997)

To setup the database, perform the following from within the Vagrant shell:

`psql -f tournament.sql`

To test the application, perform from within the Vagrant shell:

`python tournament_test.py`
