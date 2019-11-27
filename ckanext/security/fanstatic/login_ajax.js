'use strict';

(function ($) {
  var getLoginForm = function () {
    return $('#mfa-login-form')
  }

  var showQRCode = function (loginState) {
    $('#totp-secret').text(loginState.totpSecret)
    $('#mfa-setup').show()

    new QRious({
      size: 250,
      element: $('#qr-code-container')[0],
      value: loginState.totpChallengerURI
    })
  }

  var handleMfaValidation = function (validCode) {
    if (validCode) {
      getLoginForm().off('submit', validateLoginCredentials)
      getLoginForm().submit()
    } else {
      showError('mfa')
    }
  }

  var validateLoginCredentials = function (e) {
    e.preventDefault()

    var form = $(this)
    var buttons = $('[type=submit]')
    buttons.prop('disabled', true)

    $.ajax({
      url: '/mfa_login',
      method: 'POST',
      data: form.serialize(),
      success: function (loginState) {
        hideError()

        if (loginState.hasOwnProperty('mfaCodeValid')) {
          handleMfaValidation(loginState.mfaCodeValid)
          return
        }

        showMfaForm(loginState)
      },
      error: function (xhr) {
        if (xhr.status === 403) {
          showError('login')
        }
      },
      complete: function () {
        buttons.prop('disabled', false)
      }
    })
  }

  var showMfaForm = function (loginState) {
    $('#login-form').hide()
    $('#mfa-form').show()
    $('#field-mfa').focus()

    if (!loginState.mfaConfigured) {
      showQRCode(loginState)
    }
  }

  var showError = function (type) {
    if (type === 'login') {
      $('#login-fields .control-group').addClass('error')
      $('#login-fields input').val('')
      $('#login-error').show()
      $('#mfa-error').hide()
    }
    if (type === 'mfa') {
      $('#mfa-form .control-group').addClass('error')
      $('#field-mfa').val('')
      $('#mfa-error').show()
      $('#login-error').hide()
    }
    $('.error-explanation').show()
  }

  var hideError = function () {
    $('.error-explanation').hide()
    $('.control-group').removeClass('error')
  }

  $(document).ready(function () {
    getLoginForm().on('submit', validateLoginCredentials)
  })
})($)
