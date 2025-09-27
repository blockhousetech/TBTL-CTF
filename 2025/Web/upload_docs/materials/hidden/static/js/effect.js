const iconUrl = "/static/png/wallet.png";

function createFloatingIcon() {
    const icon = document.createElement("img");
    icon.src = iconUrl;
    icon.style.position = "fixed";
    icon.style.width = "32px";
    icon.style.height = "32px";
    icon.style.zIndex = "999";
    icon.style.top = `${Math.random() * 90}%`;
    icon.style.left = `${Math.random() * 90}%`;
    icon.style.opacity = "0.9";
    icon.style.transition = "transform 10s linear, opacity 3s ease-out";

    document.body.appendChild(icon);

    // Animate floating effect upward and fade out
    setTimeout(() => {
        icon.style.transform = "translateY(-100px)";
        icon.style.opacity = "0";
    }, 100);

    // Remove icon after animation
    setTimeout(() => {
        icon.remove();
    }, 10000);
}

// Periodically generate icons
setInterval(createFloatingIcon, 2000); // every 2 seconds
