const userUiQueryParams = window.location.search;


$('.form-custom-error').hide();

$(".dropsin").hover(function() {
    $('.dropsin .linkdrop').slideToggle(50);
});
$(".dropsup").hover(function() {
    $('.dropsup .linkdrop').slideToggle(50);
});
$("input.burger").click(function() {
    if ($(this).is(':checked')) {
        $('body').css('overflow', 'hidden');
    } else {
        $('body').css('overflow', 'auto');
    }
});

$(".menu-items .topLink").click(function() {
    $("input.burger").prop('checked', false);
    $('body').css('overflow', 'auto');
});

$("a.topLink").click(function() {
    $("html, body").animate({
        scrollTop: $($(this).attr("href")).offset().top + "px"
    }, {
        duration: 500,
        easing: "swing"
    });
    return false;
});


$('input[type=password]').on('keydown keyup change', function() {

    var passLenthAff = $('input#password').val().length;

    if (passLenthAff > 7) {
        $('input#confirmPassword').prop('disabled', false);
        $('input#confirmPassword').addClass('placeholderWhite');
    } else {
        $('input#confirmPassword').prop('disabled', true);
        $('input#confirmPassword').removeClass('placeholderWhite');
    }
});


$("#messengerType").change(function() {
    var messengerType = $("#messengerType").children("option:selected").val();
    if (messengerType === '3') {
        $("#messengerValue").attr('type', 'number');
        $("#messengerValue").attr('placeholder', 'Phone Number');
        $(".mvnContainer .messengerValueLabel").html('Phone Number');
        $('input[type=number]').on('keydown keyup change', function() {
            return event.keyCode !== 69 && event.keyCode !== 190 && event.keyCode !== 189
        });
    } else {
        $("#messengerValue").attr('type', 'text');
        $(".mvnContainer .messengerValueLabel").html('Messenger Username');
        $("#messengerValue").attr('placeholder', 'Messenger Username');
        $('input[type=number]').on('keydown keyup change', function() {
            return event.keyCode
        });
    }

});

jQuery('#talk').validate({});
jQuery('#advertiser-form').validate({});

jQuery('#affiliate-form').validate({
    rules: {
        email: {
            required: true,
            email: true
        },
        password: {
            minlength: 8,
        },
        confirmPassword: {
            equalTo: "#password"
        },
        accept: {
            required: true
        }
    },
    messages: {}
});

$("#confirmPassword").on("keyup", function() {
    var value_input1 = $("#password").val();
    var value_input2 = $(this).val();

    if (value_input1 != value_input2) {
        // $("#confirmPassword-error").html("Please enter the same value again.");
        $("#submit").attr("disabled", "disabled");
    } else {
        $("#submit").removeAttr("disabled");
        // $("#confirmPassword-error").html("");
    }
});


$("#email-aff").on("keyup", function() {
    var regexEmail1 = /^([a-zA-Z0-9_\.\-\+])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    var val = $("#email-aff").val();
    if (!regexEmail1.test(val) === true) {
        $('#invalid_email').css('display', 'block');

    } else {
        $('#invalid_email').css('display', 'none');
    }

});
$("#password").on("keyup", function() {
    var regexPass = /(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[~`!@#$%^&*()--+{}\[\]|\\:;"'<>,.?/_₹])[a-zA-Z0-9~`!@#$%^&*()--+{}\[\]|\\:;"'<>,.?/_₹]{8,30}$/;
    var pswd = $("#password").val();
    if (!regexPass.test(pswd) === true) {
        $('#invalid_password').css('display', 'block');

    } else {
        $('#invalid_password').css('display', 'none');
    }
});
$('#affiliate-form').submit(function(e) {
    var email = $('#affiliate-form input#email-aff').val();
    var pass = $('#password').val();
    var confirmPassword = $('#confirmPassword').val();
    var accept = $('#accept').val();
    var country = $('#country').val();
    var mType = $('#messengerType').val();
    var mVal = $('#messengerValue').val();
    var regexEmail = /^([a-zA-Z0-9_\.\-\+])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    var regexPass = /(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[~`!@#$%^&*()--+{}\[\]|\\:;"'<>,.?/_₹])[a-zA-Z0-9~`!@#$%^&*()--+{}\[\]|\\:;"'<>,.?/_₹]{8,30}$/;
    var pswd = $("#password").val();

    e.preventDefault();

    if (IsEmail(email) === false) {
        $('#invalid_email').css('display', 'block');
        return false

    } else {
        $('#invalid_email').css('display', 'none');
    }
    if ($('#accept').prop("checked") === false) {
        return false
    }

    if (!country) {
        return false;
    }

    if (!regexPass.test(pswd) === true) {
        $('#invalid_password').css('display', 'block');
        return false

    } else {
        $('#invalid_password').css('display', 'none');
    }
    if (mVal.length < 3) {
        return false
    }

    function IsEmail(email) {
        if (!regexEmail.test(email)) {
            return false;
        } else {
            return true;
        }
    }

    $.ajax({
        url: 'https://api.landing.yellana.co/register/affilate',
        method: 'POST',
        data: {
            email: email,
            password: pass,
            confirmPassword: confirmPassword,
            country: country,
            messengerType: mType,
            messengerValue: mVal,
            accept: accept,
            userUiQueryParams: userUiQueryParams
        }
    }).then(function(result) {
        if (result.success) {
            window.dataLayer = window.dataLayer || [];
            window.dataLayer.push({
                'event': 'yellanaRegAff',
                'userID': result.affilateId
            });
            window.location.href = 'https://yellana.affise.com/v2/sign/in';
        }
        var error1 = result ? .error.split('[email].data: ').join('');
        var error2 = error1.split('[password].data: ').join('');
        var error3 = error2.split('\\n').join('. ');
        $('#affiliate-form .errorfromback').html(error3);
        console.log(result.error);
    });
});

$("#email-adv").on("keyup", function() {
    var regexEmail1 = /^([a-zA-Z0-9_\.\-\+])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    var val = $("#email-adv").val();
    if (!regexEmail1.test(val) === true) {
        $('#invalid_email_adv').css('display', 'block');

    } else {
        $('#invalid_email_adv').css('display', 'none');
    }

});
$('#advertiser-form').submit(function(e) {

    var email = $('#advertiser-form input#email-adv').val();
    var company = $('#company').val();
    var regexEmailAdv = /^([a-zA-Z0-9_\.\-\+])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;

    e.preventDefault();
    if (company.length < 3) {
        return false
    }
    if (IsEmailA(email) === false) {
        $('#invalid_email_adv').css('display', 'block');
        return false

    } else {
        $('#invalid_email_adv').css('display', 'none');
    }

    function IsEmailA(email) {
        if (!regexEmailAdv.test(email)) {
            return false;
        } else {
            return true;
        }
    }

    $.ajax({
        url: 'https://api.landing.yellana.co/register/advertiser',
        method: 'POST',
        data: {
            email: email,
            company: company,
            userUiQueryParams: userUiQueryParams
        }
    }).then(function(result) {
        if (result.success) {
            window.dataLayer = window.dataLayer || [];
            window.dataLayer.push({
                'event': 'yellanaRegAdv',
                'userID': result.advertiserId
            });
            $('#advertiser-form').html('<div class="sent">Password will be created and sent to you via email automatically</div>');
        }
        var error = result ? .error.split('[email].data: ').join('');
        $('#advertiser-form .errorfromback').html(error);

    });
});
$("#email").on("keyup", function() {
    var regexEmail1 = /^([a-zA-Z0-9_\.\-\+])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    var val = $("#email").val();
    if (!regexEmail1.test(val) === true) {
        $('#invalid_email_contact').css('display', 'block');

    } else {
        $('#invalid_email_contact').css('display', 'none');
    }

});
$('#talk').submit(function(e) {

    e.preventDefault();

    var name = $('#talk input#name').val();
    var email = $('#talk input#email').val();
    var message = $('#talk #message').val();
    var regexEmailAdv = /^([a-zA-Z0-9_\.\-\+])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;


    if (IsEmailA(email) === false) {
        $('#invalid_email_contact').css('display', 'block');
        return false

    } else {
        $('#invalid_email_contact').css('display', 'none');
    }

    function IsEmailA(email) {
        if (!regexEmailAdv.test(email)) {
            return false;
        } else {
            return true;
        }
    }

    if (name.length < 3) {
        return false
    }
    if (message.length < 10) {
        return false
    }
    $.ajax({
        url: 'https://api.landing.yellana.co/contact',
        method: 'POST',
        data: {
            email: email,
            name: name,
            message: message,

        }
    }).then(function(result) {
        if (result.success) {
            $('#talk').html('<div class="sent">Thanks! We’ll contact you soon.</div>');
        }
        $('#talk .errorfromback').html(result.error);
    });
})