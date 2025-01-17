globalThis.crypto ??= require('node:crypto').webcrypto;

const appID: string = 'test';

type ResponseValue =
  | { type: 'none' }
  | { type: 'loading' }
  | { type: 'error'; message: string }
  | { type: 'success'; name: string; session_id: string | undefined };

class LernsaxAPI {
  session_id: string | undefined;
  id_counter: number;
  email: string | undefined;
  password: string | undefined;
  token: Object | undefined;
  nonce: any;

  constructor() {
    this.session_id = undefined;
    this.id_counter = 0;
    this.email = undefined;
    this.password = undefined;
    this.token = undefined;
    this.nonce = undefined;
  }

  mkReq(method: string, params: Object = {}) {
    this.id_counter += 1;

    return {
      jsonrpc: '2.0',
      method: method,
      id: this.id_counter,
      params: params,
    };
  }

  async doRequest(requestJson: any) {
    const response = await fetch('https://www.lernsax.de/jsonrpc.php', {
      method: 'POST',
      headers: {},
      body: JSON.stringify(requestJson),
      mode: 'cors',
    });

    return await response.json();
  }

  setLoginParams(email: string, password: string) {
    this.email = email;
    this.password = password;
  }

  async performLoginRequest(): Promise<ResponseValue> {
    let requestLoginJSON = [];

    if (
      this.token == undefined ||
      this.email != undefined ||
      this.password != undefined
    ) {
      console.log('Requesting Login Token...');
      requestLoginJSON.push(
        this.mkReq('login', { login: this.email, password: this.password })
      );
      requestLoginJSON.push(this.mkReq('set_focus', { object: 'trusts' }));
      requestLoginJSON.push(
        this.mkReq('register_master', {
          remote_application: appID,
          remote_title: appID,
        })
      );
      requestLoginJSON.push(this.mkReq('get_nonce'));

      let responseJson = await this.doRequest(requestLoginJSON);

      if (responseJson[0].result?.error) {
        return {
          type: 'error',
          message: `Error: ${responseJson[0].result.error}`,
        };
      }

      this.token = responseJson[2].result.trust.token;
      this.nonce = responseJson[3].result.nonce;
    }
    requestLoginJSON = [];

    const salt = btoa(
      String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))
    );

    const message = this.nonce.key + salt + this.token;
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuf = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hash = Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    requestLoginJSON.push(
      this.mkReq('login', {
        login: this.email,
        algorithm: 'sha256',
        nonce_id: this.nonce.id,
        salt,
        hash,
        application: appID,
      })
    );
    requestLoginJSON.push(this.mkReq('set_focus', { object: 'trusts' }));
    requestLoginJSON.push(this.mkReq('get_information'));

    let responseJson = await this.doRequest(requestLoginJSON);
    console.log(responseJson);
    if (responseJson[0].result?.error) {
      return {
        type: 'error',
        message: `Error: ${responseJson[0].result.error}`,
      };
    }

    this.session_id = responseJson[2].result.session_id;

    return {
      type: 'success',
      name: responseJson[0].result.user.name_hr,
      session_id: this.session_id,
    };
  }

  async fetchFiles(): Promise<any> {
    if (this.session_id == undefined) {
      return {
        type: 'error',
        message: 'Must do login first',
      };
    }

    let requestJson = [];

    requestJson.push(
      this.mkReq('set_session', { session_id: this.session_id })
    );
    requestJson.push(this.mkReq('set_focus', { object: 'files' }));
    requestJson.push(this.mkReq('get_entries'));

    const responseJson = await this.doRequest(requestJson);

    if (!Array.isArray(responseJson) || responseJson.length != 3) {
      return {
        type: 'error',
        message: 'Invalid response from server',
      };
    }

    return {
      type: 'success',
      entries: responseJson[2].result.entries,
    };
  }

  async downloadFile(file_id: string): Promise<any> {
    if (this.session_id == undefined) {
      return {
        type: 'error',
        message: 'Must do login first',
      };
    }

    let requestJson = [];

    requestJson.push(
      this.mkReq('set_session', { session_id: this.session_id })
    );
    requestJson.push(this.mkReq('set_focus', { object: 'files' }));
    requestJson.push(this.mkReq('get_file', { id: file_id }));

    const responseJson = await this.doRequest(requestJson);

    if (!Array.isArray(responseJson) || responseJson.length != 3) {
      return {
        type: 'error',
        message: 'Invalid response from server',
      };
    }

    const binaryData = Buffer.from(responseJson[2].result.file.data, 'base64');

    return {
      type: 'success',
      filename: responseJson[2].result.file.name,
      binary: binaryData,
    };
  }

  async logout() {
    let requestLogoutJSON = [];
    requestLogoutJSON.push(this.mkReq('logout'));

    let responseJson = await this.doRequest(requestLogoutJSON);
    return responseJson;
  }
}

let lernsaxAPI = new LernsaxAPI();

const main = async () => {
  let response;

  lernsaxAPI.setLoginParams('logseq@manos-dresden.lernsax.de', 'Manos2025!');

  response = await lernsaxAPI.performLoginRequest();
  console.log(response);
  await lernsaxAPI.logout();
  response = await lernsaxAPI.performLoginRequest();
  console.log(response);
  //response = await lernsaxAPI.fetchFiles();

  //response = await lernsaxAPI.downloadFile('/1/3');

  //console.log(response.binary.toString('utf-8'));
};

main();
