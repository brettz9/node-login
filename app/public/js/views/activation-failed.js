/* globals $, _, AlertDialog */
'use strict';
window.ActivationFailedView = {
  /**
   * @returns {external:jQuery} `HTMLDivElement`
   */
  accountFailedActivation () {
    // Set up the alert that displays when an account has not been activated.
    return AlertDialog.populate({
      heading: _('ActivationFailed'),
      body: _('activationCodeProvidedInvalid', {
        lb: $('<br/>')[0]
      }),
      keyboard: false,
      backdrop: 'static'
    });
  },
  /**
   * @param {external:jQuery} accountActivatedAlertDialog `HTMLDivElement`
   * @returns {external:jQuery} `HTMLButtonElement`
   */
  getOKButton (accountActivatedAlertDialog) {
    return accountActivatedAlertDialog.find('[data-name=ok]');
  }
};