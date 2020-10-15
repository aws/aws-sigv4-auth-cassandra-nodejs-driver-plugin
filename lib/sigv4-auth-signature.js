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

let CryptoJS = require ('crypto-js');

const CASSANDRA_SERVICE_NAME = 'cassandra';
const AWS4_SIGNING_ALGORITHM = 'AWS4-HMAC-SHA256';
const V4_IDENTIFIER = 'aws4_request';

/**
 * Compute the signature from signing key.
 *
 * @param {string} stringToSign - the complete string we must sign
 * @param {WordArray} signingKey - derived from date, region etc
 * @returns {WordArray} constituting the signture
 * @private
 */
function computeSignature(stringToSign, signingKey) {
  return  CryptoJS.HmacSHA256(stringToSign, signingKey);
}

/**
 * Form the authentication string which contains metadata and signature.
 *
 * @param {WordArray | string} signature - cypher-text for the request
 * @param {string} accessKeyId - Access id of AccessKey pair
 * @param {string} isoDateString - timestamp of form '2020-06-09T22:41:51.000Z'
 * @param {string} sessionToken - session token if temporary credentials
 * @returns {string} full authentication string
 * @private
 */
function formSignedString(signature, accessKeyId, isoDateString, sessionToken) {
  let result = `signature=${signature},access_key=${accessKeyId},amzdate=${isoDateString}`;

  if (sessionToken) {
    result += `,session_token=${sessionToken}`;
  }

  return result;
}

/**
 * Creates the signing key for signature.
 * This is based on the date and region
 *
 * @param {string} secretAccessKey - key from AccessKey pair
 * @param {string} credentialDateStamp - aws credential stamp, '20200609' for example
 * @param {string} region - the aws region, example 'us-west-2'
 * @returns {WordArray} binary chunk representing the signing key.
 * @private
 */
function deriveSigningKey(secretAccessKey, credentialDateStamp, region) {
  let secret = 'AWS4' + secretAccessKey;
  let dateHmac =  CryptoJS.HmacSHA256(credentialDateStamp, secret);
  let regionHmac = CryptoJS.HmacSHA256(region, dateHmac);
  let serviceHmac = CryptoJS.HmacSHA256(CASSANDRA_SERVICE_NAME, regionHmac);

  return  CryptoJS.HmacSHA256("aws4_request", serviceHmac);
}

/**
 * Transforms a date into an aws credential date stamp.
 *
 * @example 2020-06-09T22:41:51.000Z -> '20200609'
 * @param {Date} date - representing the request time
 * @returns {string} aws credential timestamp
 * @private
 */
function toCredentialDateStamp(date) {
  let result = date.toISOString().replace(/[:\-]|\.\d{3}/g, '');

  return result.substring(0, 8);
}

/**
 * Form the data that will be checked against the signature we build.
 *
 * @param {string} canonicalRequest - the formal request sorted, and made
 * unambiguous
 * @param {string} isoDateString - timestamp of form '2020-06-09T22:41:51.000Z'
 * @param {string} signingScope - description defining the request
 * @returns {string} the string that will be compared against to ensure
 * authentication
 * @private
 */
function createStringToSign(canonicalRequest, isoDateString, signingScope) {
  let digest = CryptoJS.SHA256(canonicalRequest);

  return `${AWS4_SIGNING_ALGORITHM}\n${isoDateString}\n${signingScope}\n${digest}`;
}

/**
 * Determines a scope string that is used in the plain text to be signed.
 *
 * @param {string} credentialDateStamp - aws credential stamp, '20200609' for example
 * @param {string} region - aws region such as 'us-west-2'
 * @returns {string} for example '20200609/us-west-2/cassandra/aws4_request'
 * @private
 */
function deriveSigningScope(credentialDateStamp, region) {
  return [
    credentialDateStamp,
    region,
    CASSANDRA_SERVICE_NAME,
    V4_IDENTIFIER
  ].join('/');
}

function formatXAmzCred(accessKeyId, scope) {
  return `X-Amz-Credential=${accessKeyId}%2F${encodeURIComponent(scope)}`;
}

function formatXAmzDate(timestamp) {
  return `X-Amz-Date=${encodeURIComponent(timestamp)}`
}

const ADZ_ALGORITHM_HEADER = `X-Amz-Algorithm=${AWS4_SIGNING_ALGORITHM}`;
const AMZ_EXPIRES_HEADER = "X-Amz-Expires=900";

/**
 * Creates the canonical request.  This is a sorted, unambiguous version of
 * the request that will be compared to for authentication.
 *
 * @param {string} accessKeyId - access id of the AccessKey pair
 * @param {string} signingScope - description defining the request
 * @param {string} isoDateString - timestamp of form '2020-06-09T22:41:51.000Z'
 * @param nonceHash - sha256 digest of the nonce provided in the challenge buffer
 * @returns {string} the canonical request.
 * @private
 */
function deriveCanonicalRequest(accessKeyId, signingScope, isoDateString, nonceHash) {
  let headers = [
    ADZ_ALGORITHM_HEADER,
    formatXAmzCred(accessKeyId, signingScope),
    formatXAmzDate(isoDateString),
    AMZ_EXPIRES_HEADER];

  headers.sort();

  let queryString = headers.join('&');

  return `PUT\n/authenticate\n${queryString}\nhost:${CASSANDRA_SERVICE_NAME}\n\nhost\n${nonceHash}`;

}

/**
 * Computes the signature line of a given cassandra request.
 *
 * @param {object} options
 * @param {string} options.region - region such as 'us-west-2'
 * @param {string} options.nonce - nonce provided by the challenge request
 * @param {Date} options.date - date representing the time of the request
 * @param {string} options.accessKeyId - access id of the AccessKey pair
 * @param {string} options.secretAccessKey - password/secret of the AccessKey pair
 * @param {string} options.sessionToken - optionally set when access credentials are
 * temporary.
 * @returns {string} a complete signature string.
 * @example
 * // returns
 * // 'signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z'
 * let response = computeSigV4SignatureCassandraRequest({
           region: 'us-west-2',
           nonce: '91703fdc2ef562e19fbdab0f58e42fe5',
           date: new Date(1591742511000),
           accessKeyId: 'UserID-1',
           secretAccessKey: 'UserSecretKey-1'
       });
  */
function computeSigV4SignatureCassandraRequest({
  region,
  nonce,
  date,
  accessKeyId,
  secretAccessKey,
  sessionToken
}) {

  let isoDate = date.toISOString();
  let credentialDateStamp = toCredentialDateStamp(date);
  let nonceHash = CryptoJS.SHA256(nonce);

  let signingScope = deriveSigningScope(credentialDateStamp, region);
  let cannoicalRequest = deriveCanonicalRequest(accessKeyId, signingScope, isoDate, nonceHash);

  let signingKey = deriveSigningKey(secretAccessKey, credentialDateStamp, region);
  let stringToSign = createStringToSign(cannoicalRequest, isoDate, signingScope);
  let signature = computeSignature(stringToSign, signingKey);

  return formSignedString(signature, accessKeyId, isoDate, sessionToken);
}

/**
 *  This is a namespace style object solely used to define the steps of the signing process
 *  While normally its not the best id to expose internals or to test them, because
 *  this function makes successive digests, sha hashes and encryption its easy to
 *  be off by a single property, type etc and not know where the problem occurred.
 *  this allows us to confirm each step of the signing process with a test, so
 *  we can quickly find a problem.
 *  @private
 */
const testingOnly = {
  signingSteps : {
    deriveSigningScope: deriveSigningScope,
    deriveCanonicalRequest: deriveCanonicalRequest,
    deriveSigningKey: deriveSigningKey,
    createStringToSign: createStringToSign,
    computeSignature: computeSignature,
    formSignedString: formSignedString
  }
};

module.exports = {
  computeSigV4SignatureCassandraRequest: computeSigV4SignatureCassandraRequest,
  testingOnly: testingOnly
};
