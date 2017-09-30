jQuery(function( $ ){
    $('.close-alert').click(function( e ){
        e.preventDefault();
        $.cookie('alert', 'closed', { path: '/' });
    });
});

jQuery(function( $ ){
    if( $.cookie('alert') === 'closed' ){
        $('.alert').hide();
    }
});