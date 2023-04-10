function updateResult(info){
    var divResult = document.getElementById('divResult');
    divResult.innerHTML = info;
}

function onResponseCheckStorageOK(data) {
    console.log(data);
    updateResult(data.message);
}

function check_storage()
{
    updateResult("Checking");
    $.ajax({
        url: '/admin/monitorstorage?req=checkstorage',
        method: 'POST',
        cache: false,
        dataType: "json",
        processData: false,
        success: onResponseCheckStorageOK,
        error: onResponseError
    });

}

function check_req_queue()
{
    updateResult("Dump req");
    $.ajax({
        url: '/admin/monitorstorage?req=dumpreq',
        method: 'POST',
        cache: false,
        dataType: "json",
        processData: false,
        success: onResponseCheckStorageOK,
        error: onResponseError
    });

}


function onResponseDeleteOK(data) {
    console.log(data);

    showLoading(false);
    updateResult(data.message);
}

function onResponseDeleteError(data) {
    console.log(data);

    showLoading(false);
    updateResult(data.responseText);
}



function clean_up_download()
{
    
    var txtNumDelDay = document.getElementById('txtNumDelDay');
    var days = 0;
    if (txtNumDelDay != null){
        days = txtNumDelDay.value;
    }
    if (days != '')
    {
        var i;
        var total = 3
        var ok = 0
        for (i = 0; i < total; i++) {
            var r = confirm(`Are you sure to Clean up download older than'${days}' days? \nConfirmed ${i}/${total}`);
            if (r == true) {
                ok ++
            } else {
                break
            }
        }

        if (ok >= total){
            showLoading(true)
            $.ajax({
                url: `/admin/monitorstorage?req=cleandownload&days=${days}`,
                method: 'POST',
                success: onResponseDeleteOK,
                error: onResponseDeleteError
            });
        }
        else{
            alert(`Not enough confirmation to delete (need ${total})\n`)
        }
        
       
    }
    else{
        alert(`Invalid days ${days}`);
    }
    
}