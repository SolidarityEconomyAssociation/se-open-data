# -*- ruby -*-
Gem::Specification.new do |s|
  s.name        = 'se_open_data'
  s.version     = '1.0.0'
  s.licenses    = ['GPL-3.0-or-later']
  s.summary     = "Solidarity Economy Open Data transforms"
  s.description = <<-HERE
    This is a collection of Ruby classes for transforming 3rd party data into 
    a uniform schema and thence into RDF linked open data.
  HERE
  s.authors     = ["Solidarity Economy Association"]
  s.email       = 'tech.accounts@solidarityeconomy.coop'
  s.files       =  Dir['lib/**/*.rb'] + Dir['bin/**'] + Dir['resources/**']
  s.executables.concat %w(seod export-lime-survey)
  s.homepage    = 'https://github.com/SolidarityEconomyAssociation/se-open-data'
  s.metadata    = { "source_code_uri" => "https://github.com/SolidarityEconomyAssociation/se-open-data" }

  s.add_runtime_dependency('httparty')
  s.add_runtime_dependency('levenshtein')
  s.add_runtime_dependency('linkeddata')
  s.add_runtime_dependency('nokogiri')
  s.add_runtime_dependency('normalize_country')
  s.add_runtime_dependency('opencage-geocoder')
  s.add_runtime_dependency('prawn')
  s.add_runtime_dependency('prawn-table')
  
  s.add_development_dependency('minitest')
end

# Ubuntu prereqs
# sudo apt-get install build-essential patch ruby-dev zlib1g-dev liblzma-dev git dev-libzip ruby ruby-bundler
