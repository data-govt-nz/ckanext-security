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
    hideError()

    var form = $(this)
    var buttons = $('[type=submit]')
    buttons.prop('disabled', true)

    $.ajax({
      url: '/api/mfa_login',
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
          return
        }

        showError()
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
    $('#mfa-form-active').val('true')

    if (!loginState.mfaConfigured) {
      showQRCode(loginState)
    }
  }

  var showError = function (type) {
    hideError() // always reset state before displaying errors

    var errorElId = '#' + (type || 'unknown') + '-error'
    $(errorElId).show()
    if (!type) {
      $('#invalid-entries').hide()
    }
    $('.control-group').addClass('error')
    $('.error-explanation').show()
  }

  var hideError = function () {
    $('.error-explanation').hide()
    $('.error-explanation li').hide()
    $('#invalid-entries').show()
    $('.control-group').removeClass('error')
  }

  $(document).ready(function () {
    getLoginForm().on('submit', validateLoginCredentials)
  })
})($)
