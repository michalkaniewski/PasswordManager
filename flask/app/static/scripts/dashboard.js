function showPassword(e) {
    const passId = e.target.parentElement.id;
    const item = document.getElementById(passId);
    const masterKey = item.getElementsByTagName("input")[0].value;
    if (masterKey === "") {
        return;
    }
    console.log(masterKey);
    fetch(`/password/${passId}`, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({key: masterKey})
    }).then(res => {
        if (res.ok) {
            res.text().then(text => {
                const masterKey = item.getElementsByTagName("input")[1].value=text;
            });
            
        }
    });
}


window.onload = function () {
    const list = document.getElementById("passwords-list");
    const itemsCol = list.getElementsByTagName("li");
    const items = Array.prototype.slice.call(itemsCol);
    items.forEach(it => {
        it.getElementsByTagName("button")[0].onclick = (e) => showPassword(e);
    });
}