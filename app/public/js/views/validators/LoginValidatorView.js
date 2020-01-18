/* globals $, _ */
'use strict';

/**
* @typedef {PlainObject} LoginInfoElements
* @property {external:jQuery} name
* @property {external:jQuery} pass
*/

window.LoginValidatorView = {
  /**
   * @returns {LoginInfoElements}
   */
  getFormFields () {
    return {
      user: $('[data-name="user"]')[0],
      pass: $('[data-name="pass"]')[0]
    };
  },

  errorMessages: {
    PleaseEnterValidUserName: _('PleaseEnterValidUserName'),
    PleaseEnterValidPassword: _('PleaseEnterValidPassword'),
    LoginFailure: _('LoginFailure'),
    PleaseCheckYourUserNameOrPassword: _('PleaseCheckYourUserNameOrPassword')
  },

  messages: {
    LinkToResetPasswordMailed: _('LinkToResetPasswordMailed'),
    EmailNotFound: _('EmailNotFound'),
    ProblemTryAgainLater: _('ProblemTryAgainLater')
  }
};
