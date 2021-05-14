#include "loader.h"

__declspec( noinline ) bool verify_loader( )
{
	VMProtectBeginMutation( "verify_loader" );

	auto throw_error = [] ( unsigned int code )
	{
		char buffer[256] = { 0 };
		sprintf_s( buffer, xorstr_( "Submit this error code to support staff: %d\n" ), code );
		MessageBoxA( HWND_DESKTOP, buffer, xorstr_( "Error" ), MB_ICONERROR );

		ExitProcess( 0 );
	};

#ifndef UNICODE
	const auto file_mapping = OpenFileMappingW( FILE_MAP_READ, false, xorstr_( L"Global\\LplMU4kg5vq7JILyVCyQnSpipfSUosn1iUf" ) );
#else
	const auto file_mapping = OpenFileMappingA( FILE_MAP_READ, false, xorstr_( "Global\\LplMU4kg5vq7JILyVCyQnSpipfSUosn1iUf" ) );
#endif

	if ( !file_mapping )
	{
		throw_error( failure_file_not_opened );
		return false;
	}

	const auto file_view = reinterpret_cast<uint8_t*>( MapViewOfFile( file_mapping, FILE_MAP_READ, 0, 0, 0x1000 ) );

	if ( !file_view )
	{
		throw_error( failure_file_not_mapped );
		CloseHandle( file_mapping );
		return false;
	}

	loader_challenge client_buffer;
	memcpy( &client_buffer, file_view + loader_data_offset, sizeof( loader_challenge ) );

	// magic check 1

	if ( client_buffer.magic1 != loader_magic_1 )
	{
		throw_error( failure_struct_magic_invalid );
		CloseHandle( file_mapping );
		return false;
	}

	// magic check 2

	if ( client_buffer.magic2 != loader_magic_2 )
	{
		throw_error( failure_struct_magic_invalid );
		CloseHandle( file_mapping );
		return false;
	}

	// first time check

	LARGE_INTEGER counter{};
	QueryPerformanceCounter( &counter );

	int64_t decrypted_time = client_buffer.create_time ^ loader_time_encryption_key;

	if ( decrypted_time < 0 )
	{
		throw_error( failure_struct_time_invalid );
		CloseHandle( file_mapping );
		return false;
	}

	// time check, 5 minute max since loader was opened

	int64_t difference = counter.QuadPart - decrypted_time;

	// printf( "[+] difference: %lu\n", difference );

	if ( difference > 300000000 )
	{
		throw_error( failure_struct_time_invalid );
		CloseHandle( file_mapping );
		return false;
	}

	CloseHandle( file_mapping ); // super important
	VMProtectEnd( );
	return true;
}