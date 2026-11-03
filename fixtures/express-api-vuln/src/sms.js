// vg-expect: secrets/provider-key
const TWILIO_API_KEY = '{{FAKE:twilio_api_key:sms}}';
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;

module.exports = { TWILIO_API_KEY, TWILIO_ACCOUNT_SID };
