/* ==========================================================================
   JEREMY GIMENEZ - CYBERSECURITY PORTFOLIO
   script.js  -  small, dependency-free enhancements.

   WHAT THIS FILE DOES:
     1. Opens/closes the mobile menu.
     2. Highlights the nav link for the section you are viewing.
     3. Opens screenshots in an enlarged "lightbox" view.
     4. Fills in the current year in the footer.
   You should not need to edit this file to update content.
   ========================================================================== */
(function () {
  "use strict";

  /* ------------------------------------------------------------------
     1. MOBILE MENU
     ------------------------------------------------------------------ */
  var toggle = document.querySelector(".nav-toggle");
  var links = document.getElementById("primary-nav");

  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });

    /* Close the menu after tapping a link (mobile) */
    links.addEventListener("click", function (e) {
      if (e.target.tagName === "A") {
        links.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* ------------------------------------------------------------------
     2. ACTIVE SECTION IN NAV  (uses IntersectionObserver - no libraries)
     ------------------------------------------------------------------ */
  var navAnchors = Array.prototype.slice.call(
    document.querySelectorAll('.nav-links a[href^="#"]')
  );

  if ("IntersectionObserver" in window && navAnchors.length) {
    var sections = navAnchors
      .map(function (a) { return document.querySelector(a.getAttribute("href")); })
      .filter(Boolean);

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          var id = "#" + entry.target.id;
          navAnchors.forEach(function (a) {
            if (a.getAttribute("href") === id) {
              a.setAttribute("aria-current", "true");
            } else {
              a.removeAttribute("aria-current");
            }
          });
        });
      },
      { rootMargin: "-45% 0px -50% 0px", threshold: 0 }
    );

    sections.forEach(function (s) { observer.observe(s); });
  }

  /* ------------------------------------------------------------------
     3. SCREENSHOT LIGHTBOX
     Each gallery thumbnail is a <button data-full="..." data-caption="...">
     ------------------------------------------------------------------ */
  var lightbox = document.getElementById("lightbox");
  var thumbs = Array.prototype.slice.call(
    document.querySelectorAll(".gallery button.thumb")
  );

  if (lightbox && thumbs.length) {
    var lbImg = lightbox.querySelector("img");
    var lbCap = lightbox.querySelector(".lightbox-caption");
    var lbClose = lightbox.querySelector(".lightbox-close");
    var lastFocused = null;

    function openLightbox(btn) {
      lastFocused = btn;
      var full = btn.getAttribute("data-full");
      var img = btn.querySelector("img");
      var caption = btn.getAttribute("data-caption") || (img ? img.alt : "");
      lbImg.setAttribute("src", full);
      lbImg.setAttribute("alt", img ? img.alt : "");
      lbCap.textContent = caption;
      lightbox.classList.add("open");
      lightbox.setAttribute("aria-hidden", "false");
      lbClose.focus();
      document.body.style.overflow = "hidden";
    }

    function closeLightbox() {
      lightbox.classList.remove("open");
      lightbox.setAttribute("aria-hidden", "true");
      document.body.style.overflow = "";
      if (lastFocused) lastFocused.focus();
    }

    thumbs.forEach(function (btn) {
      btn.addEventListener("click", function () { openLightbox(btn); });
    });

    lbClose.addEventListener("click", closeLightbox);
    lightbox.addEventListener("click", function (e) {
      if (e.target === lightbox) closeLightbox();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && lightbox.classList.contains("open")) closeLightbox();
    });
  }

  /* ------------------------------------------------------------------
     4. FOOTER YEAR
     ------------------------------------------------------------------ */
  var yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());
})();
