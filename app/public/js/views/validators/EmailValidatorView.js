/* globals $, _ */
'use strict';

/**
* @typedef {PlainObject} EmailInfoElements
* @property {external:jQuery} name
* @property {external:jQuery} email
* @property {external:jQuery} user
* @property {external:jQuery} pass
*/

window.EmailValidatorView = {
  /**
   * @returns {AccountInfoElements}
   */
  getFormFields () {
    return {
      retrievePasswordModal: $('#retrieve-password'),
      retrievePasswordAlert: $('#retrieve-password .alert'),
      retrievePasswordForm: $('#retrieve-password #retrieve-password-form')
    };
  },

  /**
   * @param {string} msg
   */
  addSuccess (msg) {
    const {retrievePasswordAlert} = this.getFormFields();
    retrievePasswordAlert.attr('class', 'alert alert-success');
    retrievePasswordAlert.text(msg);
  },

  messages: {
    PleaseEnterValidEmailAddress: _('PleaseEnterValidEmailAddress')
  }
};
