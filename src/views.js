// SEC003 — XSS
function renderUsername(req, res) {
    const username = req.query.name
    document.getElementById("user").innerHTML = username
}

// SEC002 — SQL injection
function getProduct(req, db) {
    const id = req.params.id
    db.query("SELECT * FROM products WHERE id = " + id)
}