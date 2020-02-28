/* globals $ */

'use strict';

window.ResetPasswordView = {
  /**
   * @returns {external:jQuery} `HTMLFormElement`
   */
  getSetPasswordForm () {
    return $('#set-password-form');
  },

  /**
   * @returns {external:jQuery} `HTMLDivElement`
   */
  getSetPasswordDialog () {
    return $('#set-password');
  },

  /**
   * @returns {external:jQuery} `HTMLInputElement`
   */
  getPassword () {
    return $('[data-name="reset-pass"]');
  },

  /**
   * @returns {external:jQuery} `HTMLButtonElement`
   */
  getSetPasswordSubmit () {
    return $('[data-name="reset-password-submit"]');
  }
};
