globalThis.crypto ??= require('node:crypto').webcrypto;
var path = require('path');

const appID: string = 'test';

type ResponseValue =
  | { type: 'none' }
  | { type: 'loading' }
  | { type: 'error'; message: string }
  | { type: 'success'; name: string; session_id: string | undefined };

interface Entry {
  id: string;
  parent_id: string;
  ordinal: number;
  name: string;
  description: string;
  type: 'file' | 'folder'; // Assuming type is either "file" or "folder"
  size: number;
  readable: number;
  writable: number;
  sparse: number;
  mine: number;
  shared: number;
  created: object; // You might replace this with a more specific type like `Date` if you know the structure
  modified: object; // Same as above
  effective: object; // Same as above
  preview: number;
}

class LernsaxAPI {
  session_id: string | undefined;
  id_counter: number;
  email: string | undefined;
  password: string | undefined;
  token: Object | undefined;
  nonce: any;
  entries: Entry[];

  constructor() {
    this.session_id = undefined;
    this.id_counter = 0;
    this.email = undefined;
    this.password = undefined;
    this.token = undefined;
    this.nonce = undefined;
    this.entries = [];

    try {
      this.token = localStorage.getItem('lernsaxapi_login_token') || undefined;
    } catch (error) {
      this.token = undefined;
    }
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

      try {
        localStorage.setItem('lernsaxapi_login_token', this.token as string);
      } catch {}
      this.nonce = responseJson[3].result.nonce;
    } else if (this.token == undefined) {
      return {
        type: 'error',
        message: `Missing Email/Password or Login Token`,
      };
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

    this.entries = responseJson[2].result.entries;

    return responseJson[2].result.entries;
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

    if (
      !Array.isArray(responseJson) ||
      responseJson.length != 3 ||
      responseJson[2].result.return != 'OK'
    ) {
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

  async uploadNewFile(
    data: string,
    filename: string,
    parent_folder_id: string
  ): Promise<any> {
    if (this.session_id == undefined) {
      return {
        type: 'error',
        message: 'Must do login first',
      };
    }

    const base64Data = Buffer.from(data, 'binary').toString('base64');

    let requestJson = [];

    requestJson.push(
      this.mkReq('set_session', { session_id: this.session_id })
    );
    requestJson.push(this.mkReq('set_focus', { object: 'files' }));
    requestJson.push(
      this.mkReq('add_file', {
        name: filename,
        folder_id: parent_folder_id,
        data: base64Data,
      })
    );

    const responseJson = await this.doRequest(requestJson);

    if (
      !Array.isArray(responseJson) ||
      responseJson.length != 3 ||
      responseJson[2].result.return != 'OK'
    ) {
      return {
        type: 'error',
        message: 'Invalid response from server',
      };
    }

    await this.fetchFiles();

    return {
      type: 'success',
    };
  }

  async addFolder(
    folder_name: string,
    parent_folder_name: string
  ): Promise<any> {
    if (this.session_id == undefined) {
      return {
        type: 'error',
        message: 'Must do login first',
      };
    }

    const parent_folder_id = this.getObjectId(parent_folder_name);

    let requestJson = [];

    requestJson.push(
      this.mkReq('set_session', { session_id: this.session_id })
    );
    requestJson.push(this.mkReq('set_focus', { object: 'files' }));
    requestJson.push(
      this.mkReq('add_folder', {
        name: folder_name,
        folder_id: parent_folder_id,
      })
    );

    const responseJson = await this.doRequest(requestJson);

    if (
      !Array.isArray(responseJson) ||
      responseJson.length != 3 ||
      responseJson[2].result.return != 'OK'
    ) {
      return {
        type: 'error',
        message: 'Invalid response from server',
      };
    }

    await this.fetchFiles();

    return {
      type: 'success',
    };
  }

  async deleteFile(file_id: string) {
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
    requestJson.push(
      this.mkReq('delete_file', {
        id: file_id,
        skip_trash: 0,
      })
    );

    const responseJson = await this.doRequest(requestJson);
    if (
      !Array.isArray(responseJson) ||
      responseJson.length != 3 ||
      responseJson[2].result.return != 'OK'
    ) {
      return {
        type: 'error',
        message: 'Invalid response from server',
      };
    }

    await this.fetchFiles();

    return {
      type: 'success',
    };
  }

  async deleteFolder(folder_path: string) {
    if (this.session_id == undefined) {
      return {
        type: 'error',
        message: 'Must do login first',
      };
    }

    const folder_id = this.getObjectId(folder_path);

    let requestJson = [];

    requestJson.push(
      this.mkReq('set_session', { session_id: this.session_id })
    );
    requestJson.push(this.mkReq('set_focus', { object: 'files' }));
    requestJson.push(
      this.mkReq('delete_folder', {
        id: folder_id,
      })
    );

    const responseJson = await this.doRequest(requestJson);
    if (
      !Array.isArray(responseJson) ||
      responseJson.length != 3 ||
      responseJson[2].result.return != 'OK'
    ) {
      return {
        type: 'error',
        message: 'Invalid response from server',
      };
    }

    await this.fetchFiles();

    return {
      type: 'success',
    };
  }

  async uploadFile(data: string, filename: string, parent_folder_name: string) {
    const file_id = await this.getObjectId(
      path.join(parent_folder_name, filename)
    );

    console.log(file_id);

    if (file_id != 'NOTFOUND') {
      await this.deleteFile(file_id);
    }

    const folder_id = await this.getObjectId(parent_folder_name);

    const result = await this.uploadNewFile(data, filename, folder_id);

    return result;
  }

  async logout() {
    let requestLogoutJSON = [];
    requestLogoutJSON.push(this.mkReq('logout'));

    let responseJson = await this.doRequest(requestLogoutJSON);
    return responseJson;
  }

  getObjectId(filePath: string): string {
    if (filePath == '/') {
      return '/';
    }
    const filePathParts = filePath.replace(/\\/g, '/').split('/').reverse();
    let possibleParents = this.entries.map((entry) => entry.id);
    const history: { id: string; parent: string }[] = [];

    let possibleEntries: any[] = [];
    for (const part of filePathParts) {
      possibleEntries = this.entries
        .filter(
          (entry) => entry.name === part && possibleParents.includes(entry.id)
        )
        .map((entry) => ({ id: entry.id, parent: entry.parent_id }));
      history.push(...possibleEntries);
      possibleParents = possibleEntries.map((entry) => entry.parent);
    }

    if (possibleEntries.length === 0) {
      return 'NOTFOUND';
    }

    if (possibleEntries.length === 1) {
      const temp = history.filter((entry) =>
        entry.id.includes(possibleEntries[0].id)
      );
      return temp.sort(
        (a, b) =>
          (a.id.match(/\//g)?.length || 0) - (b.id.match(/\//g)?.length || 0)
      )[temp.length - 1].id;
    }

    return 'AMBIGIOUS';
  }
}

let lernsaxAPI = new LernsaxAPI();

const main = async () => {
  let response;

  lernsaxAPI.setLoginParams('logseq@manos-dresden.lernsax.de', 'Manos2025!');

  response = await lernsaxAPI.performLoginRequest();

  console.log(response);

  await lernsaxAPI.fetchFiles();

  //let data = await lernsaxAPI.downloadFile(file_id);
  //console.log(data.binary.toString('utf-8'));

  //let r = await lernsaxAPI.uploadFile(
  //  'testupload1UPDATED2',
  //  'testUpload1.txt',
  //  'testOrdner'
  //);
  let r = await lernsaxAPI.addFolder('testOrdner3', '/');
  console.log(r);
};

main();
