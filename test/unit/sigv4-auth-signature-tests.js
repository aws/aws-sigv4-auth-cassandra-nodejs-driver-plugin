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

const CryptoJS = require ('crypto-js');
const authsign = require('../../lib/sigv4-auth-signature');
const assert = require('assert');


describe('Signing Steps',  () => {
  const signingSteps = authsign.testingOnly.signingSteps;

  // epoch milliseconds representing 2020-06-09T22:41:51.000Z.
  const requestDate = new Date(1591742511000);
  const isoDateStamp = '2020-06-09T22:41:51.000Z';
  const credentialTimeStamp = "20200609";

  const region = "us-west-2";
  const accessKeyId = 'UserID-1';
  const secretAccessKey ="UserSecretKey-1";
  const nonce = '91703fdc2ef562e19fbdab0f58e42fe5';

  const signature = '7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87';
  const signingScope =  '20200609/us-west-2/cassandra/aws4_request';
  const canonicalRequest = 'PUT\n'
      + '/authenticate\n'
      + 'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=UserID-1%2F20200609%2Fus-west-2%2Fcassandra%2Faws4_request&X-Amz-Date=2020-06-09T22%3A41%3A51.000Z&X-Amz-Expires=900\n'
      + 'host:cassandra\n'
      + '\n'
      + 'host\n'
      + 'ddf250111597b3f35e51e649f59e3f8b30ff5b247166d709dc1b1e60bd927070';

  const stringToSign = 'AWS4-HMAC-SHA256\n'
      + '2020-06-09T22:41:51.000Z\n'
      + '20200609/us-west-2/cassandra/aws4_request\n'
      + 'bf5cc15759befc37fc35689dcdd7938a9ad042b6326f537c4c5eecaa2ebf911e';
  const signingKey = CryptoJS.enc.Hex.parse('7fb139473f153aec1b05747b0cd5cd77a1186d22ae895a3a0128e699d72e1aba');
  const computedFullResult ='signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z';

  describe('#deriveSigningScope()', () => {
    it('should work with example above', ()  => {
      let actual = signingSteps.deriveSigningScope(credentialTimeStamp, region);

      assert.equal(actual, signingScope);
    });
  });

  describe('#deriveCannonicalRequest()', () => {
    it('should work with example above', () => {
      let nonce1 = '91703fdc2ef562e19fbdab0f58e42fe5';
      let nonceHash = CryptoJS.SHA256(nonce1);
      let actual = signingSteps.deriveCanonicalRequest(accessKeyId, signingScope,
          isoDateStamp, nonceHash);

      assert.equal(actual, canonicalRequest);
    });
  });

  describe('#createStringToSign()', () => {
    it('should format everything correctly', () => {
      let actual = signingSteps.createStringToSign(canonicalRequest, isoDateStamp,
          signingScope);

      assert.equal(actual, stringToSign);
    });
  });

  describe('#deriveSigningKey()', () => {
    it('should produce key when given valid input', () => {
      let actual = signingSteps.deriveSigningKey(secretAccessKey, credentialTimeStamp,
          region);

      assert.notStrictEqual(actual, signingKey);
    });
  });

  describe('#computeSignature()', () => {
    it('should come up with expected signature', () => {
      let actual = signingSteps.computeSignature(stringToSign, signingKey);

      assert.equal(actual.toString(), signature);
    });
  });

  describe('#formSignedString()', () => {
    it('should format everything correctly', () =>  {

      let amzDate = '2020-06-09T22:41:51.000Z';
      let actual = signingSteps.formSignedString(signature, accessKeyId, amzDate);

      assert.equal(actual, computedFullResult);
    });
  });

  describe('#computeSigV4SignatureCassandraRequest()', () => {
    it('should produce valid result when no temporary creds', () =>  {
      let actual = authsign.computeSigV4SignatureCassandraRequest({
            region: region,
            nonce: nonce,
            date: requestDate,
            accessKeyId: accessKeyId,
            secretAccessKey: secretAccessKey,
      });
      assert.equal(actual, computedFullResult);
    });
    it('should produce valid result when given temporary creds', () =>  {
      const sessionToken = 'sess-token-1';
      const computedFullResultWithSession ='signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87'
          + ',access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z'
          + ',session_token=sess-token-1';

      const actual = authsign.computeSigV4SignatureCassandraRequest({
        region: region,
        nonce: nonce,
        date: requestDate,
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
        sessionToken: sessionToken
      });
      assert.equal(actual, computedFullResultWithSession);
    });
  });
});
