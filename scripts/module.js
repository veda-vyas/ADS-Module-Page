jQuery(function( $ ){
    $('.close-alert').click(function( e ){
        e.preventDefault();
        $.cookie('alert', 'closed', { path: '/' });
    });
    $('#showinstructions').click(function( e ){
        $('.alert').show();
    });
});

jQuery(function( $ ){
    if( $.cookie('alert') === 'closed' ){
        $('.alert').hide();
    }
});