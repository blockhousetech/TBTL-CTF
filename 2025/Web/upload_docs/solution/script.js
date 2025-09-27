var items = document.querySelectorAll('li');
items.forEach((li, index) => {
    document.querySelector('a[data-index="' + index.toString() + '"]').id = document.getElementsByName(index.toString())[0].innerHTML;
});

var effects = "static/js/effect.js";
let backup = [].filter.constructor("return this")();

const { href } = backup[effects] || { href: effects};

const script = document.createElement('script');
script.src = href;
document.body.appendChild(script);
