#ifndef JSON_SPIRIT_WRITER_TEMPLATE
#define JSON_SPIRIT_WRITER_TEMPLATE

//          Copyright John W. Wilkinson 2007 - 2009.
// Distributed under the MIT License, see accompanying file LICENSE.txt

// json spirit version 4.03

#include "json_spirit_value.h"

#include <cassert>
#include <sstream>
#include <iomanip>

namespace json_spirit
{
    inline char to_hex_char( unsigned int c )
    {
        assert( c <= 0xF );

        const char ch = static_cast< char >( c );

        if( ch < 10 ) return '0' + ch;

        return 'A' - 10 + ch;
    }

    template< class String_type >
    String_type non_printable_to_string( unsigned int c )
    {
        // Silence the warning: typedef â€˜Char_typeâ€™ locally defined but not used [-Wunused-local-typedefs]
        // typedef typename String_type::value_type Char_type;

        String_type result( 6, '\\' );

        result[1] = 'u';

        result[ 5 ] = to_hex_char( c & 0x000F ); c >>= 4;
        result[ 4 ] = to_hex_char( c & 0x000F ); c >>= 4;
        result[ 3 ] = to_hex_char( c & 0x000F ); c >>= 4;
        result[ 2 ] = to_hex_char( c & 0x000F );

        return result;
    }

    template< typename Char_type, class String_type >
    bool add_esc_char( Char_type c, String_type& s )
    {
        switch( c )
        {
            case '"':  s += to_str< String_type >( "\\\"" ); return true;
            case '\\': s += to_str< String_type >( "\\\\" ); return true;
            case '\b': s += to_str< String_type >( "\\b"  ); return true;
            case '\f': s += to_str< String_type >( "\\f"  ); return true;
            ca