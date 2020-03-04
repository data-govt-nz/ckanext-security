'use strict';

(function($) {
    $(document).ready(function() {
        var qrRenderTarget = $('#qr-code-container')
        var totpUri = $('#totp-uri');

        if (qrRenderTarget.length === 0 || totpUri.length === 0) {
            throw new Error('Can\'t find the required elements to render a qr code')
        }
        new QRious({
            size: 250,
            element: qrRenderTarget,
            value: totpUri.val()
        })
    })
})($)