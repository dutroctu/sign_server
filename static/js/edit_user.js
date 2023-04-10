
function edit_user(ev)
{
    showLoading(true)
    ev.preventDefault();
    var form_data = new FormData(this)
    form_data.append("name", document.getElementById('name').value);
    userid = document.getElementById('id').value
    $.ajax({
        url: `/edit_user/${userid}`,
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
    $('#edit_user').on('submit', edit_user);
});