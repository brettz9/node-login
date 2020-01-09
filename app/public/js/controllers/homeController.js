/* global $ */
'use strict';

window.HomeController = {
  init () {
    // handle user logout
    $('#btn-logout').click(() => { this.attemptLogout(); });

    // confirm account deletion
    $('#account-form-btn1').click(() => {
      $('.modal-confirm').modal('show');
    });

    // handle account deletion
    $('.modal-confirm .submit').click(() => {
      this.deleteAccount();
    });

    this.deleteAccount = () => {
      $('.modal-confirm').modal('hide');
      $.ajax({
        url: '/delete',
        type: 'POST',
        success (data) {
          this.showLockedAlert(
            'Your account has been deleted.<br>' +
            'Redirecting you back to the homepage.'
          );
        },
        error (jqXHR) {
          console.log(jqXHR.responseText + ' :: ' + jqXHR.statusText);
        }
      });
    };

    this.attemptLogout = function () {
      $.ajax({
        url: '/logout',
        type: 'POST',
        data: {logout: true},
        success: (data) => {
          this.showLockedAlert(
            'You are now logged out.<br>Redirecting you back to the homepage.'
          );
        },
        error (jqXHR) {
          console.log(jqXHR.responseText + ' :: ' + jqXHR.statusText);
        }
      });
    };

    this.showLockedAlert = function (msg) {
      $('.modal-alert').modal({
        show: false, keyboard: false, backdrop: 'static'
      });
      $('.modal-alert .modal-header h1').text('Success!');
      $('.modal-alert .modal-body p').html(msg);
      $('.modal-alert').modal('show');
      $('.modal-alert button').click(() => {
        location.href = '/';
      });
      setTimeout(() => { location.href = '/'; }, 3000);
    };
  },
  onUpdateSuccess () {
    $('.modal-alert').modal({show: false, keyboard: true, backdrop: true});
    $('.modal-alert .modal-header h1').text('Success!');
    $('.modal-alert .modal-body p').html('Your account has been updated.');
    $('.modal-alert').modal('show');
    $('.modal-alert button').off('click');
  }
};
