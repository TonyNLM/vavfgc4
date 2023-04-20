var CryptoJS = require("crypto-js");
var axios = require('axios').default;
var bip32 = require("bip32");
var bip39 = require("bip39");

function sha256(input /** string */) {
  return CryptoJS.SHA256(input).toString().toUpperCase();
}

function aes256Encrypt(content /*string*/, secret /*string*/) {
  return CryptoJS.AES.encrypt(content, secret).toString();
}

function aes256Decrypt(cipher /** base 64 string */, secret /** string */) {
  var bytes = CryptoJS.AES.decrypt(cipher, secret);
  return bytes.toString(CryptoJS.enc.Utf8);
}

//for each contact, store these fields
var sharedsecret =
  "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
var peerid = 1; //identifies the peer
var keyid = 1; //which key are we on, rotates every 7 days (or sooner, depending)

function getKeyFromSecret(sharedsecret, peerid, id) {
  const derivePath =
    "m/192'/168'/0'/1'" + "/" + peerid.toString() + "/" + id.toString();

  const seed = Buffer.from(sharedsecret, "hex");
  const derivedSeed = bip32.fromSeed(seed).derivePath(derivePath).publicKey;

  return derivedSeed.toString("hex");
}

function getAdderssFromSecret(sharedsecret, peerid, id) {
    const derivePath =
    "m/127'/0'/0'/1'" + "/" + peerid.toString() + "/" + id.toString();

  const seed = Buffer.from(sharedsecret, "hex");
  const derivedSeed = bip32.fromSeed(seed).derivePath(derivePath).publicKey;

  return derivedSeed.toString("hex");
}

function hashMessage(message){
    bigstring = message.prev+message.address+message.chash+message.timestamp.toString()+message.ttl.toString()+message.nonce.toString()
    return sha256(bigstring)
}

//constant, can get via /difficulty or just hardcode somewhere
var difficulty = "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

function validPOW(message){
	var hashint = BigInt("0x"+message.hash);
	var difficultyint = BigInt(difficulty);
	return hashint < difficultyint
}

function iteratePOW(message){
	var nonce=0;
	do{
	message.nonce=nonce;
	message.hash = hashMessage(message);
	nonce += 1;
	}
	while(!validPOW(message));
}


function newMessage(plaintext, sharedsecret, peerid, keyid) {
  var c = aes256Encrypt(plaintext, getKeyFromSecret(sharedsecret,peerid,keyid))
    var message = {
        hash : '',
        prev : '001A8390C75BB921D4CD3BC51A020838C8938F06094EA85659181981F675125A', //hash of genesis, might change
        address : getAdderssFromSecret(sharedsecret,peerid,keyid),
        chash : sha256(c),
        timestamp : Math.floor(Date.now() / 1000),
        ttl : 604800,
        nonce : 0,
        content : c
    }
    iteratePOW(message)
    return message
}

var API_URL = "http://vml1wk063.cse.ust.hk"

/** takes address:string, returns a list of messages */
async function getMessage(address) {
  try {
    const response = await axios.get(API_URL+'/client/message?address='+address);
    if (response.status==200){
      return response.data //axios already return JSON. This is a list of messages with this address
    }
  } catch (error) {
    if (error.response.status==404){
      //TODO: dont panic if not found
    }else{
    console.error(error);
    }
  }
}


/**  */
async function postMessage(message) {
  try {
    const response = await axios.post(API_URL+'/client/message', message);
    if (response.status==200){
      return true
    }
  } catch (error) {
    return false;
  }
}



export function App(){
  return ""
}

console.log(getKeyFromSecret(sharedsecret, 0));
console.log(validPOW({hash:"555"}))
console.log(newMessage("",sharedsecret,peerid,keyid))
