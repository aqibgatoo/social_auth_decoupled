<?php

namespace Drupal\social_auth_decoupled;

use Drupal\Core\Access\CsrfTokenGenerator;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * Contains all logic that is related to Drupal user management.
 */
class SocialAuthDecoupledUserManager extends SocialAuthUserManager {

  /**
   * The CSRF token generator.
   *
   * @var \Drupal\Core\Access\CsrfTokenGenerator
   */
  protected $csrfToken;

  /**
   * Injects the csrf_token service.
   *
   * @param \Drupal\Core\Access\CsrfTokenGenerator $csrf_token
   *   The csrf_token.
   */
  public function setCsrfToken(CsrfTokenGenerator $csrf_token) {
    $this->csrfToken = $csrf_token;
  }

  /**
   * Creates and/or authenticates an user.
   *
   * @param string $email
   *   The user's email address.
   * @param string $name
   *   The user's name.
   * @param string $id
   *   The user's id in provider.
   * @param string|bool $picture_url
   *   The user's picture.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   A redirect response.
   */
  public function authenticateUser($email, $name, $id = NULL, $picture_url = FALSE) {
    // Tries to load the user by their email.
    $drupal_user = $this->loadUserByProperty('mail', $email);
    // If user email has already an account in the site.
    if ($drupal_user) {
      // Authenticates and redirect existing user.
      return $this->authenticateExistingUser($drupal_user);
    }

    $drupal_user = $this->createUser($name, $email);
    // If the new user could be registered.
    if ($drupal_user) {
      // Download profile picture for the newly created user.
      if ($picture_url) {
        $this->setProfilePic($drupal_user, $picture_url, $id);
      }
      // Authenticates and redirect new user.
      return $this->authenticateNewUser($drupal_user);
    }
    $this->nullifySessionKeys();

    throw new BadRequestHttpException('You could not be authenticated, please contact the administrator');

  }

  /**
   * Authenticates and redirects existing users in authentication process.
   *
   * @param \Drupal\user\UserInterface $drupal_user
   *   User object to authenticate.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   A redirect response.
   */
  public function authenticateExistingUser(UserInterface $drupal_user) {
    // If Admin (user 1) can not authenticate.
    if ($this->isAdminDisabled($drupal_user)) {
      $this->nullifySessionKeys();
      throw new BadRequestHttpException('Authentication for Admin (user 1) is disabled.');
    }

    // If user can not login because of their role.
    $disabled_role = $this->isUserRoleDisabled($drupal_user);
    if ($disabled_role) {
      throw new BadRequestHttpException("Authentication for '@role' role is disabled.", ['@role' => $disabled_role]);
    }

    // If user could be logged in.
    $response_data = $this->loginUser($drupal_user);
    if ($response_data) {
      return $response_data;
    }
    else {
      throw new BadRequestHttpException("Your account has not been approved yet or might have been canceled, please contact the administrator");
    }
  }

  /**
   * Authenticates and redirects new users in authentication process.
   *
   * @param \Drupal\user\UserInterface $drupal_user
   *   User object to login.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   A redirect response.
   */
  public function authenticateNewUser(UserInterface $drupal_user) {
    // If the account needs admin approval.
    if ($this->isApprovalRequired()) {
      $this->nullifySessionKeys();
      throw new BadRequestHttpException("Your account was created, but it needs administrator's approval");
    }

    // If the new user could be logged in.
    $response_data = $this->loginUser($drupal_user);
    if ($response_data) {
      return $response_data;
    }
  }

  /**
   * Logs the user in.
   *
   * @param \Drupal\user\Entity\User $user
   *   User object.
   *
   * @return array|bool
   *   Reterun the user info array or false.
   */
  public function loginUser(User $user) {
    // Check that the account is active and log the user in.
    if ($user->isActive()) {
      $this->userLoginFinalize($user);

      // Send basic metadata about the logged in user.
      $response_data = [];
      if ($user->get('uid')->access('view', $user)) {
        $response_data['current_user']['uid'] = $user->id();
      }
      if ($user->get('roles')->access('view', $user)) {
        $response_data['current_user']['roles'] = $user->getRoles();
      }
      if ($user->get('name')->access('view', $user)) {
        $response_data['current_user']['name'] = $user->getAccountName();
      }
      $response_data['csrf_token'] = $this->csrfToken->get('rest');

      $logout_route = $this->routeProvider->getRouteByName('user.logout.http');
      // Trim '/' off path to match \Drupal\Core\Access\CsrfAccessCheck.
      $logout_path = ltrim($logout_route->getPath(), '/');
      $response_data['logout_token'] = $this->csrfToken->get($logout_path);

      return $response_data;
    }

    throw new BadRequestHttpException('Login for user @user prevented. Account is blocked.', ['@user' => $user->getAccountName()]);
  }

}
