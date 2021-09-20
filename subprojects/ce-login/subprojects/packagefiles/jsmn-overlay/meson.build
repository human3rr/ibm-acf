project('jsmn', 'cpp',
	license: 'MIT',
	version: '1.1.0',
	meson_version: '>=0.55',
	default_options: 'cpp_std=c++17')

headers = [
	'jsmn.h',
]

inc_dir = include_directories([ '.' ] )
jsmn_dep = declare_dependency(
	version: meson.project_version(),
	include_directories: inc_dir)

pkg = import('pkgconfig')
pkg_dirs = ['.', 'jsmn']
pkg.generate(
	name: 'jsmn',
	filebase: 'jsmn',
	subdirs: pkg_dirs,
	version: meson.project_version(),
	description: 'Minimalistic JSON parser in C')
