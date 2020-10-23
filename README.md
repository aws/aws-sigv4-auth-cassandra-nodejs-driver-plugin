# IMPORTANT: Latest Version

The current version is 1.0.2. Please see the [changelog](./CHANGELOG.md) for details on version history.

# What

This package implements an authentication plugin for the open-source Datastax NodeJS Driver for Apache Cassandra. The driver enables you to add authentication information to your API requests using the AWS Signature Version 4 Process (SigV4). Using the plugin, you can provide users and applications short-term credentials to access Amazon Keyspaces (for Apache Cassandra) using AWS Identity and Access Management (IAM) users and roles.

The plugin depends on the AWS SDK for NodeJS. It uses `AWSCredentialsProvider` to obtain credentials. You must specify the service endpoint to use for the connection.
You can provide the Region in the constructor programmatically, via the `AWS_REGION` environment variable.

The full documentation for the plugin is available at
[Amazon Keyspaces AWS Docs](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.credentials.html#programmatic.credentials.SigV4_KEYSPACES).


# Using the Plugin

The following sections describe how to use the authentication plugin for the open-source DataStax NodeJS Driver for Cassandra to access Amazon Keyspaces.

## SSL Configuration

The first step is to get an Amazon digital certificate to encrypt your connections using Transport Layer Security (TLS). The DataStax NodeJS driver must use an SSL trust store so that the client SSL engine can validate the Amazon Keyspaces certificate on connection. To use the trust store and create a certificate, see [Using a Cassandra Java Client Driver to Access Amazon Keyspaces Programmatically](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.drivers.html#using_java_driver).

## Region Configuration

Before you can start using the plugin, you must configure the AWS Region that the plugin will use when authenticating. This is required because SigV4 signatures are Region-specific. For example, if you are connecting to the `cassandra.us-east-2.amazonaws.com` endpoint, the Region must be `us-east-2`. For a list of available AWS Regions and endpoints, see [Service Endpoints for Amazon Keyspaces](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.endpoints.html).

You can specify the Region using one of the following four methods:

* Environment Variable
* System Property
* Constructor
* Configuration

## Environment Variable

You can use the `AWS_REGION` environment variable to match the endpoint that you are communicating with by setting it as part of your application start-up, as follows.

``` shell
$ export AWS_Region=us-east-1
```

## Add the Authentication Plugin to the Application

The authentication plugin supports version 4.x of the DataStax NodeJS Driver for Cassandra. To add this application use 

```bash
$ npm install aws-sigv4-auth-cassandra-plugin --save
```

## How to use the Authentication Plugin

When using the open-source DataStax NodeJS driver, the connection to your Amazon Keyspaces endpoint is represented by the `Client` class. 

### Programmatically Configure the Driver

When using the DataStax NodeJS driver, you interact with Amazon Keyspaces primarily through the `Client` class.

To use the authentication plugin, you set a Region-specific instance of SigV4AuthProvider as the authentication provider, as in the following example.

1. Create a `SigV4AuthProvider` from plugin.
1. Add an SSL context using `AmazonRootCA1.pem` ssl and Keyspaces endpoint. 
1. Set the local data center to the region name, in this example it is `us-west-2`. 
The local data center is used by the driver for routing of requests, and it is required when the builder is constructed with `addContactPoints`.
1. Set the authentication provider to a new instance of the `SigV4AuthProvider`.
You can specify the Region for the endpoints that you’re using in the constructor for `SigV4AuthProvider`, as in the following example. 
Or, you can set the environment variable or system property as shown previously.

The following code example demonstrates the previous steps.

``` js
const cassandra = require('cassandra-driver');
const fs = require('fs');
const sigV4 = require('aws-sigv4-auth-cassandra-plugin');

const auth = new sigV4.SigV4AuthProvider({
    region: 'us-west-2', 
    accessKeyId:'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'});

const sslOptions1 = {
  ca: [
      fs.readFileSync('~/.cassandra/AmazonRootCA1.pem', 'utf-8')],
  host: 'cassandra.us-west-2.amazonaws.com',
  rejectUnauthorized: true
};


const client = new cassandra.Client({
  contactPoints: ['cassandra.us-west-2.amazonaws.com'],
  localDataCenter: 'us-west-2',
  authProvider: auth,
  sslOptions: sslOptions1,
  protocolOptions: { port: 9142 }
});


const query = 'SELECT * FROM system_schema.keyspaces';

client.execute(query).then(
    result => console.log('Row from Keyspaces %s', result.rows[0]))
    .catch( e=> console.log(`${e}`));
```
