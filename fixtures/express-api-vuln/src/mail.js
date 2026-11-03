const sgMail = require('@sendgrid/mail');

// vg-expect: secrets/provider-key
sgMail.setApiKey('{{FAKE:sendgrid:mail}}');

module.exports = { sgMail };
