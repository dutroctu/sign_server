

function add_user(ev)
{
    showLoading(true)
    ev.preventDefault();
    var form_data = new FormData(this)

    $.ajax({
        url: '/backup',
        method: 'POST',
        cache: false,
        contentType: false,
        processData: false,
        data: form_data,
        success: onResponseOK,
        error: onResponseError
    });

}

$(function(){
    $('#backup').on('submit', add_user);
});