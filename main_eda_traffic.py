from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
from typing import List, Optional
from EDAXuan.nettraffic.edapcap import process_csv,generate_ip_map,generate_network_graph,analyze_ip_flows,num_event
from EDAXuan.nettraffic.edapcap import plot_traffic_trend,plot_time_sum_column_trend,count_artifacts,plot_totlen_pkts_distribution,plot_address_distribution_barchart
from EDAXuan.nettraffic.edapcap import plot_top_ip_pairs_by_frame_len,summarize_column,plot_protocol_pie_chart,plot_column_distribution_barchart
import pandas as pd
from datetime import datetime


app = FastAPI()

# Biến toàn cục để lưu DataFrame
global_df = None

# Đọc csv từ hàm process_csv
@app.get("/traffic/readcsv/")
def process_and_read_csv(input_file_path: str = Query(..., description="The path to the input CSV file")):
    global global_df
    try:
        processed_file_path = process_csv(input_file_path)
        global_df = pd.read_csv(processed_file_path)
        print (global_df["Timestamp"])
        # Chuyển đổi DataFrame thành JSON
        json_data = global_df.to_json(orient="records", lines=True)

        # Trả về chuỗi JSON
        return json_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

# M1 return html
@app.get("/traffic/tab1/M1_generate_ip_map/", response_class=HTMLResponse)
def tgenerate_ip_map(
    geoip_db_path: str = Query('./EDAXuan/nettraffic/GeoLite2-City.mmdb', description="The path to the GeoIP database"),
    output_html_path: str = Query(r"./EDAXuan/nettraffic/output/ip_map.html", description="The output HTML file path")
):
    global global_df
    if global_df is not None:
        try:
            # Gọi hàm generate_ip_map với các tham số đã cung cấp
            result_path = generate_ip_map(global_df, geoip_db_path, output_html_path)
            
            # Đọc nội dung của file HTML
            with open(result_path, 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            # Trả về nội dung HTML
            return HTMLResponse(content=html_content)
            
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="File not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded")
    

@app.get("/traffic/tab1/M2_net-graph/")
def tget_network_graph():
    global global_df
    if global_df is not None:
        try:
            graph_data = generate_network_graph(global_df)
            return graph_data
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded")


@app.get("/traffic/tab1/M3_ip-flows/")
def tanalyze_ip_flows():
    global global_df
    if global_df is not None:
        try:
            graph_data = analyze_ip_flows(global_df)
            return graph_data
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please call /readcsv/ first.")
    
# tab2/M0  
@app.get("/traffic/tab2/M0_event-count/")
def tnum_events():
    global global_df
    if global_df is not None:
        try:
            event_count = num_event(global_df)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please call /readcsv/ first.")
    
# tab2 /M1
# ngày "D", giờ "h" phút "min"
@app.get("/traffic/tab2/M1_traffic_trend/")
def tplot_traffic_trend(time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global global_df
    if global_df is not None:
        try:
            # print(start_time)
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            print(start_time)
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            event_count = plot_traffic_trend(global_df, time_sign, start_time_dt, end_time_dt)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
# tab2/m2   column = Time_Delta or Totlen Pkts    dùng lại hàm ở tab4 M5 column="TotLen Fwd Pkts" M6 column="TotLen Bwd Pkts"
@app.get("/traffic/tab2/M2_time_sum_column_trend/{column}")
def tplot_time_sum_column_trend(column:str, time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = plot_time_sum_column_trend(global_df, column, time_sign, start_time_dt, end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
# tab3/m1
@app.get("/traffic/tab2/M1_count_artifacts/")
def tcount_artifacts():
    global global_df
    if global_df is not None:
        try:
                     
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = count_artifacts(global_df)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
# tab3/M2
@app.get("/traffic/tab3/M2_totlen_pkts_distribution/")
def tplot_totlen_pkts_distribution(start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetim
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time= datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            print("zo")
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = plot_totlen_pkts_distribution(global_df, num_bins=8, start_time=start_time, end_time=end_time)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")

# tab3/M3+M4   column=Source IP or Destination IP
@app.get("/traffic/tab3/M3_address_distribution_barchart/{top}/{column}")
def tget_address_distribution_barchart(top: int, column: str, start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_address_distribution_barchart(global_df, top=top, start_time=start_time, end_time=end_time, column=column)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
    
# tab3/M5  
@app.get("/traffic/tab3/M5_top_ip_pairs_by_frame_len/{top}")
def tplot_top_ip_pairs_by_frame_len(top: int, start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_top_ip_pairs_by_frame_len(global_df, top=top, start_time=start_time, end_time=end_time)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")   



# tab4/m1
@app.get("/traffic/tab4/M1_summarize_column/")
def tsummarize_column():
    global global_df
    if global_df is not None:
        try:
                     
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = summarize_column(global_df)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    


# tab4/m2 column=Protocol
@app.get("/traffic/tab4/M2_protocol_pie_chart")
def tplot_protocol_pie_chart(start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_protocol_pie_chart(global_df, start_time=start_time, end_time=end_time)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")   
    

# tab4/M3,4 column="Application Protocol" or "Source Port" or "Destination Port"
@app.get("/traffic/tab4/M3_protocol_pie_chart/{column}/{top}")
def tplot_column_distribution_barchart(top: int, column: str, start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_column_distribution_barchart(global_df, top =top, start_time=start_time, end_time=end_time,column=column)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")      
    

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8080)
    
    


    
    

    

    
    
    

    

    
    

    

    
    





    

    







    
