// Todo: For selectors, we might directly load the view files here so that
//   we don't tie our tests to specific selectors

describe('Root (Login) - Accessibility', function () {
  // https://www.npmjs.com/package/cypress-axe
  it('Root has no detectable a11y violations on load', () => {
    cy.visitURLAndCheckAccessibility('/');
  });
});

describe('Root (Login)', function () {
  beforeEach(() => {
    cy.task('deleteAllAccounts');
    cy.task('addAccount');
    cy.visit('/');
  });

  it('Visit root and login with Remember Me', function () {
    /*
    cy.visit('/reset');

    // Signs up but no UI-only way to get and add activation code
    //   needed for login; however, keeping below for reference in
    //   the event we decide to add a more precise yet slower UI
    //   test from end-to-end
    cy.visit('/signup');
    cy.get('[data-name="name"]').type('Brett');
    cy.get('[data-name="email"]').type('brettz9@example.com');
    cy.get('[data-name="country"]').select('US');
    cy.get('[data-name="user"]').type('bretto');
    cy.get('[data-name="pass"]').type('abc123456');
    cy.get('[data-name="pass-confirm"]').type('abc123456');
    cy.get('[data-name=account-form] [data-name=action2]').click();
    cy.get('[data-name=modal-alert] [data-name=ok]').click({
      timeout: 20000
    });
    cy.location('pathname', {
      timeout: 10000
    }).should('eq', '/');
    */

    cy.get('[data-name="user"]').type('bretto');
    cy.get('[data-name="pass"]').type('abc123456');
    cy.get('[data-name="btn_sign_in"]').click();
    cy.getCookie('login').should('have.property', 'value');

    cy.get('[data-name=account-form] .btn-danger').click();
    cy.get('[data-name=modal-confirm] .btn-danger').click();

    cy.get('[data-name=modal-alert] [data-name=modal-title]').contains(
      'Success!'
    );
    cy.location('pathname', {
      timeout: 10000
    }).should('eq', '/home');
  });

  it('Visit root and login with Remember Me button disabled', function () {
    cy.get('[data-name=btn_remember]').click();
    cy.get('[data-name="user"]').type('bretto');
    cy.get('[data-name="pass"]').type('abc123456');
    cy.get('[data-name="btn_sign_in"]').click();
    cy.getCookie('login').should('not.exist');

    cy.get('[data-name=account-form] .btn-danger').click();
    cy.get('[data-name=modal-confirm] .btn-danger').click();

    cy.get('[data-name=modal-alert] [data-name=modal-title]').contains(
      'Success!'
    );
    cy.location('pathname', {
      timeout: 10000
    }).should('eq', '/home');
  });

  it('Retrieve lost password', function () {
    cy.get('[data-name="forgot-password"]').click();
    cy.get('[data-name=email]').type('brettz9@example.com');
    cy.get('[data-name=retrieve-password-submit]').click();
    cy.get('[data-name=alert]').contains(
      'A link to reset your password was emailed to you',
      {
        timeout: 20000
      }
    );
  });

  // 'Sorry. There was a problem, please try again later.',
  it(
    'Err upon attempt to retrieve lost password for non-existent email',
    function () {
      cy.get('[data-name="forgot-password"]').click();
      cy.get('[data-name=email]').type('bad@bad-email.com');
      cy.get('[data-name=retrieve-password-submit]').click();
      cy.get('[data-name=alert]').contains(
        'Email not found. Are you sure you entered it correctly?',
        {
          timeout: 20000
        }
      );
    }
  );

  it('Cancel retrieve password dialog', function () {
    cy.get('[data-name="forgot-password"]').click();
    cy.get('[data-name="retrieve-password-cancel"]').click();
    cy.get('[data-name=login] [data-name="user"]', {
      timeout: 8000
    }).should(
      'have.focus'
    );
  });

  it('Should validate against missing user value', function () {
    cy.get('[data-name="pass"]').type('abc123456');
    cy.get('[data-name="btn_sign_in"]').click();
    cy.get('[data-name="user"]').should((pass) => {
      expect(pass[0].checkValidity()).to.equal(false);
    });
  });
  it('Should validate against missing pass value', function () {
    cy.get('[data-name="user"]').type('bretto');
    cy.get('[data-name="btn_sign_in"]').click();
    cy.get('[data-name="pass"]').should((pass) => {
      expect(pass[0].checkValidity()).to.equal(false);
    });
  });
});
