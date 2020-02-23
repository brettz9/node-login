/* globals AccountValidator, setupFormValidation, SignupView */
'use strict';

(() => {
const name = SignupView.getName();
name.focus();

const accountForm = SignupView.setAccountSettings();

// redirect to homepage when cancel button is clicked
const redirectToRoot = () => {
  location.href = '/';
};
const actionButton = SignupView.getActionForAccountForm(accountForm);
actionButton.click(redirectToRoot);

setupValidationSubmission();

/**
 * @returns {void}
 */
function setupValidationSubmission () {
  const av = new AccountValidator({signup: true});

  setupFormValidation({
    form: accountForm[0],
    validate () {
      av.validateForm();
    }
  });
  accountForm.ajaxForm({
    success (responseText, status, xhr, $form) {
      if (status === 'success') {
        onCreatedSuccess();
      }
    },
    error (e) {
      switch (e.responseText) {
      case 'email-taken':
        av.showInvalidEmail();
        break;
      case 'username-taken':
        av.showInvalidUserName();
        break;
      default:
        break;
      }
    }
  });
}

/**
 * @returns {void}
 */
function onCreatedSuccess () {
  const accountCreatedAlertDialog = SignupView.accountCreated();
  // redirect to homepage on new account creation, add short
  //  delay so user can read alert window
  SignupView.getAccountCreatedOkButton(accountCreatedAlertDialog).click(() => {
    setTimeout(redirectToRoot, 300);
  });
  accountCreatedAlertDialog.modal('show');
}
})();
