'use strict';

(function($) {
    $(document).ready(function() {
        var qrRenderTarget = $('#qr-code-container')[0]
        var totpInput = $('#totp-uri')[0]

        if (!qrRenderTarget || !totpInput) {
            throw new Error('Can\'t find the required elements to render a qr code')
        }
        new QRious({
            size: 250,
            element: qrRenderTarget,
            value: $(totpInput).val()
        })
    })
})($)