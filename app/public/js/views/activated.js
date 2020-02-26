/* globals $, _, AlertDialog */
'use strict';
window.ActivatedView = {
  /**
   * @returns {external:jQuery} `HTMLDivElement`
   */
  accountActivated () {
    // Set up the alert that displays when an account has been activated
    return AlertDialog.populate({
      heading: _('Activated'),
      body: _('yourAccountHasBeenActivated', {
        lb: $('<br/>')[0]
      }),
      keyboard: false,
      backdrop: 'static'
    });
  },
  /**
   * @param {external:jQuery} accountFailedActivationAlertDialog
   *  `HTMLDivElement`
   * @returns {external:jQuery} `HTMLButtonElement`
   */
  getOKButton (accountFailedActivationAlertDialog) {
    return accountFailedActivationAlertDialog.find('[data-name=ok]');
  }
};