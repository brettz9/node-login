describe('Signup', function () {
  beforeEach(() => {
    cy.visit('/reset');
  });
  it('Visit Signup', function () {
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
  });
  // https://www.npmjs.com/package/cypress-axe
  it('Signup has no detectable a11y violations on load', () => {
    cy.visitURLAndCheckAccessibility('/signup');
  });
});