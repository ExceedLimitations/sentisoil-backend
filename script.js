window.addEventListener('scroll', function () {
    const header = document.querySelector('.header');
    const navBar = document.querySelector('.nav-bar');
    
    if (window.scrollY > 20) {
      header.classList.add('scrolled');
      navBar.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
      navBar.classList.remove('scrolled');
    }
  });
