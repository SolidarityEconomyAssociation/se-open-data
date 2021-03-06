module SeOpenData
  module Utils
    require "csv"
    require "prawn"
    require "prawn/table"
    require "fileutils"

    # Document generator - generates errror reports
    #
    # It uses prawn to generate a formatted PDF
    class ErrorDocumentGenerator
      def initialize(title, introduction, name_header, domain_header, headers, create_title = true,
                     output_dir: 'docs')
        @title_pdf = File.join(output_dir, "titledoc.pdf")
        @ids_pdf = File.join(output_dir, "idsdups.pdf")
        @fields_pdf = File.join(output_dir, "fieldups.pdf")
        @geo_pdf = File.join(output_dir, "geodups.pdf")
        @lat_lon_pdf = File.join(output_dir, "latlngdups.pdf")
        @name_header = name_header
        @domain_header = domain_header
        @headers = headers

        return unless create_title

        pdf = Prawn::Document.new
        pdf.text title, :align => :center, :size => 25 # heading
        pdf.pad(10) { } #padding

        pdf.text introduction, :size => 12  # sum

        # Create the output directory before rendering
        FileUtils.mkdir_p output_dir
        pdf.render_file @title_pdf

        #create intro doc only if no other intro doc exists
      end

      def create_doc(title, description, similar_entries, filename)
        return if similar_entries.empty?
        pdf = Prawn::Document.new
        pdf.text title, :align => :center, :size => 25 # heading
        pdf.pad(10) { } #padding

        pdf.text description, :size => 12  # sum
        first = nil
        similar_entries.each { |subarr|
          #subbarr :: [row,row,row]
          # $stderr.puts subarr
          name = subarr.first[@name_header].encode("Windows-1252", invalid: :replace, undef: :replace, replace: "")
          pdf.pad_top(30) { pdf.text name, :size => 15 } # mini heading name
          pdf.text "We think these are the same", :size => 10
          data = subarr.map { |row|
            #Remove empties
            rowarr = []
            row[@domain_header] = "" #rm domain
            #use only rows that have something in them
            @headers.each { |h| rowarr.push(row[h]) if (row[h] != nil && row[h] != "") }
            strrow = rowarr.join(",").encode("Windows-1252", invalid: :replace, undef: :replace, replace: "")
            first = [strrow] if first == nil

            [strrow]
          }
          pdf.table(data) do
            rows(0).width = 72
          end

          pdf.pad(5) { } #padding
          pdf.text "This is the entry we have kept", :size => 10 # heading
          pdf.text first.join
          first = nil
        }

        pdf.render_file filename
      end

      #similar_entries:: string => array of row
      def add_similar_entries_id(title, description, similar_entries)
        create_doc(title, description, similar_entries, @ids_pdf)
      end

      #similar_entries::
      def add_similar_entries_fields(title, description, similar_entries)
        create_doc(title, description, similar_entries, @fields_pdf)
      end

      #similar_entries::
      def add_similar_entries_fields_after_geo_uniform(title, description, similar_entries)
        create_doc(title, description, similar_entries, @geo_pdf)
      end

      def add_similar_entries_latlon(title, description, similar_entries)
        create_doc(title, description, similar_entries, @lat_lon_pdf)
      end

      def generate_document_from_row_array(title, description, file_name, rows_array, headers, verbose_fields = [])
        pdf = Prawn::Document.new
        pdf.text title, :align => :center, :size => 25 # heading
        pdf.pad(10) { } #padding

        pdf.text description, :size => 12  # sum
        pdf.pad(10) { } #padding

        data = rows_array.map { |row|
          #Remove empties
          rowarr = []
          #use only rows that have something in them
          headers.reject { |h| verbose_fields.include?(h) }.each { |h| rowarr.push(row[h]) if (row[h] != nil && row[h] != "") }
          verbose_fields.each { |h| rowarr.push("#{h}: #{row[h]}") if (row[h] != nil && row[h] != "") }
          strrow = rowarr.join(",").encode("Windows-1252", invalid: :replace, undef: :replace, replace: "")
          [strrow]
          
        }
        pdf.table(data) do
          rows(0).width = 72
        end

        # Create the directory before rendering
        FileUtils.mkdir_p File.dirname(file_name)
        pdf.render_file file_name
      end
    end
  end
end
