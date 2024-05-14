package main

import (
	"fmt"
	hackeronereq "toptechh1cve/utility"
)

func main() {
	//Headers for the CSV Data File
	// fmt.Println("CVEs-NAME" + "," + "Reports Count" + "," + "Vendor/Tech")
	offset := 0
	for {
		data, err := hackeronereq.GetData(offset)
		if err != nil {
			fmt.Println(err)
			break // Exit the loop if there's an error fetching data
		}
		for _, edge := range data.Data.Ranked_cve_entries.Edges {
			for _, vendors := range edge.Node.Vendors {
				// output := edge.Node.Cve_id + "," + fmt.Sprintf("%d", edge.Node.Reports_submitted_count) + "," + products
				fmt.Println(vendors)
				if edge.Node.Reports_submitted_count < 20 {
					return
				}

			}
		}
		offset += 40
	}
}
