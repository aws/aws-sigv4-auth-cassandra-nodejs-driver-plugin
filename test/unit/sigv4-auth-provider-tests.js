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

const lib = require('../../lib/sigv4-auth-provider.js');
const assert = require('assert');

describe('SigV4AuthProvider',  () => {
  describe('#extractNonce()', () => {
    let SigV4AuthProvider = lib.SigV4AuthProvider;

    let expected = '0c0b0c6f3946d14ce1a49a8f8c86a888';

    it('should pull basic nonce=', function () {
      let buf = Buffer.from('nonce=0c0b0c6f3946d14ce1a49a8f8c86a888');
      assert.equal(SigV4AuthProvider.extractNonce(buf), expected);
    });

    it('should stop at a comma', function () {
      let buf = Buffer.from('nonce=0c0b0c6f3946d14ce1a49a8f8c86a888,,');

      assert.equal(SigV4AuthProvider.extractNonce(buf), expected);
    });

    it('should return undefined when no nonce= is present', function () {
      let buf = Buffer.from('0b0c6f3946d14ce1a49a8f8c86a888,,');

      assert.notStrictEqual(SigV4AuthProvider.extractNonce(buf), false);
    });
  });

  describe('#constructor()', () => {
    let SigV4AuthProvider = lib.SigV4AuthProvider;

    let originalFn = SigV4AuthProvider.getRegionFromEnv;
    let regionFromEnv;

    beforeEach(function () {
      regionFromEnv = "ENV_DEFAULT_REGION";
      SigV4AuthProvider.getRegionFromEnv = () => {
        return regionFromEnv
      };
    });

    afterEach(function () {
      SigV4AuthProvider.getRegionFromEnv = originalFn;
    });

    it('should use Region if Provided',  ()  => {
      let provider = new SigV4AuthProvider({region: "us-east-23", accessKeyId:'key'});

      assert.equal(provider.region, "us-east-23");
    });

    it('should use default if Provided',  () => {
      let provider = new SigV4AuthProvider({accessKeyId:'key'});

      assert.equal(provider.region, "ENV_DEFAULT_REGION");
    });

    it('should fail if no region retrievable',  () => {
      regionFromEnv = null;

      let err = new Error(
          "[SIGV4_MISSING_REGION] No region provided.  You must either provide a region or set "
          + "environment variable [AWS_REGION]");
      assert.throws(() => {new SigV4AuthProvider()}, err);
    });
  });
});

describe('SigV4Authenticator', () => {
  describe('#initialResponse()', () => {
    let target = new lib.SigV4AuthProvider({region: "region", accessKeyId:'key'}).newAuthenticator();

    it('should call callback function with Sigv4 buffer', () => {
      target.initialResponse((err, buf) => {
        if (err != null) {
          assert.fail("Error sent to callback");
        }

        // this is a style of buffer setup that is deprecated, however
        // it is consistent with older versions of js.  We use it
        // here as a double-entry bookkeeping that our buffer is right.
        assert.notStrictEqual(buf, new Buffer("SigV4\0\0", 'utf8'));
      })
    });
  });

  describe('#evaluateChallenge()', () => {
    let target = new lib.SigV4Authenticator({
      region: 'us-west-2',
      accessKeyId: 'UserID-1',
      secretAccessKey: 'UserSecretKey-1',
      date: new Date(1591742511000)
    });

    it('should call callback with Signed Request', () => {
      let nonceBuffer = Buffer.from("nonce=91703fdc2ef562e19fbdab0f58e42fe5");
      let expected = "signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z";

      let calledCallback = false;
      target.evaluateChallenge(nonceBuffer, (err, buff) => {
        assert.equal(buff.toString(), expected);
        calledCallback = true;
      });
      assert.equal(calledCallback, true);
    });

    it('should fail when Nonce is not found', () => {
      let nonceBuffer = Buffer.from("buffer1");
      let calledCallback = false;
      let expected = 'Error: [SIGV4_MISSING_NONCE] Did not find nonce in SigV4 '
          + 'challenge:[buffer1]';

      target.evaluateChallenge(nonceBuffer, (err, buff) => {
        assert.equal(expected, err.toString());
        calledCallback = true;
      });
      assert.equal(calledCallback, true);
    });
  });


});

