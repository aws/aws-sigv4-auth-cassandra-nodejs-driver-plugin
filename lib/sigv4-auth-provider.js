/*
 *   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

'use strict';

const util = require("util");
const cass = require('cassandra-driver');
const AWS = require('aws-sdk');
const sigv4 = require('./sigv4-auth-signature');

/**
 * Creates a new instance of the Authenticator provider.
 *
 * @classdesc Provides an SigV4 [Authenticator]{@link cass.auth.AuthProvider} instances to be used when
 * connecting to a host.
 * @extends cass.auth.AuthProvider
 * @param {object} options
 * @param {string} options.region - aws region such as 'us-west-2'.
 * @param {string} options.accessKeyId - if not provided default to using profile
 * @param {string} options.secretAccessKey - AWS profile iff accessKeyId is not provided.
 * @param {string} options.sessionToken - use this if you are using temporary credentials.
 * @constructor
 */
function SigV4AuthProvider( {
    region,
    accessKeyId,
    secretAccessKey,
    sessionToken} = {}) {
  if (accessKeyId) {
    const credentials = new AWS.Credentials(accessKeyId, secretAccessKey, sessionToken);
    this.chain = new AWS.CredentialProviderChain([credentials]);
  } else {
    this.chain = new AWS.CredentialProviderChain();
  }

  this.region = region || SigV4AuthProvider.getRegionFromEnv();

  // validate region
  if (!this.region) {
    throw new Error('[SIGV4_MISSING_REGION] No region provided.  You must either provide a region or set '
    + 'environment variable [AWS_REGION]');
  }
}

util.inherits(SigV4AuthProvider, cass.auth.AuthProvider);

/**
 * Pull region from enviornment
 * @returns {string}
 */
SigV4AuthProvider.getRegionFromEnv = () => {
  return process.env.AWS_REGION;
};

/**
 * Pull the nonce from a challenge buffer
 *
 * @param {Buffer} buf - Buffer with service response.
 * @returns {string} - should be the string representing the nonce=.
 */
SigV4AuthProvider.extractNonce = (buf) => {
  let bufAsString = buf.toString();

  let res1 = bufAsString.split("nonce=");

  if (res1.length < 2) {
    return undefined;
  }

  let res2 = res1[1].split(',');

  return res2[0];
};


/**
 * Returns a new [Authenticator] instance to
 * be used for SigV4 authentication.
 * @override
 * @returns {Authenticator}
 */
SigV4AuthProvider.prototype.newAuthenticator = function () {
  return new SigV4Authenticator({
    region: this.region,
    chain: this.chain,
  });
};

/**
 * Creates a new instance of the Authenticator for SigV4.
 *
 * Generally speaking you should avoid constructing this directly, and instead
 * really on {@link SigV4AuthProvider} newAuthenticator method
 *
 * @classdesc allows SigV4 to be used as an authentication method.
 * @extends cass.auth.Authenticator
 * @param {object} options
 * @param {string} options.region - aws region such as 'us-west-2'.
 * @param {AWS.CredentialProviderChain} options.chain - provider chain with appropriate credentials
 * @param {Date} options.date - fixed date to use.  If not provided, we use current date.
 * @constructor
 */
function SigV4Authenticator({
  region,
  chain,
  date
} = {}) {
  this.chain = chain;
  this.region = region;
  this.date = date;
}

util.inherits(SigV4Authenticator, cass.auth.Authenticator);

/**
 * Initially called when validation is performed.
 *
 * @param {function} callback - called when sending desired authentication
 * indicator
 */
SigV4Authenticator.prototype.initialResponse = function (callback) {
  // we need to tell the system we want sigV4.
  const responseBuffer = Buffer.from("SigV4\0\0", 'utf8');
  callback(null, responseBuffer);

};

/**
 * Called when Service responds with a challenge request.
 * We are then responsible for extracting the nonce, and providing a SigV4
 * signature.
 * @param {Buffer} challenge - buffer of challenge
 * @param {function} callback - function used with existing credentials.
 */
SigV4Authenticator.prototype.evaluateChallenge = function (challenge, callback) {
  let nonce = SigV4AuthProvider.extractNonce(challenge);
  if (!nonce) {
    callback(new Error(`[SIGV4_MISSING_NONCE] Did not find nonce in SigV4 challenge:[${challenge}]`), null);
    return;
  }

  let dateToUse  = this.date || new Date();

  this.chain.resolvePromise().then((creds) => {
    let signedString =  sigv4.computeSigV4SignatureCassandraRequest({
      region: this.region,
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken,
      date: dateToUse,
      nonce: nonce
    });
    callback(null, Buffer.from(signedString));
  });
};

module.exports =
{
  SigV4AuthProvider: SigV4AuthProvider,
  SigV4Authenticator: SigV4Authenticator
};
