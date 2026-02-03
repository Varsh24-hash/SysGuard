
import React from 'react';
import {
  ComposedChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { SyscallData } from '../types';

interface SyscallChartProps {
  data: SyscallData[];
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-slate-900 border border-slate-700 p-3 rounded-xl shadow-2xl text-xs backdrop-blur-md">
        <p className="font-black text-white mb-2 uppercase tracking-tighter border-b border-slate-800 pb-1">{label}()</p>
        <div className="space-y-1">
          <p className="flex justify-between gap-4">
            <span className="text-slate-500 font-bold uppercase">Baseline:</span>
            <span className="font-mono text-slate-300">{payload[0].value}</span>
          </p>
          <p className="flex justify-between gap-4">
            <span className="text-sky-500 font-bold uppercase">Test:</span>
            <span className="font-mono text-white">{payload[1].value}</span>
          </p>
          <p className="flex justify-between gap-4 border-t border-slate-800 pt-1 mt-1">
            <span className="text-orange-400 font-bold uppercase">Deviation:</span>
            <span className="font-mono text-orange-400 font-black">{payload[2]?.value.toFixed(1)}%</span>
          </p>
        </div>
      </div>
    );
  }
  return null;
};

const SyscallChart: React.FC<SyscallChartProps> = ({ data }) => {
  return (
    <div className="h-[400px] w-full mt-4">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart
          data={data}
          margin={{ top: 20, right: 20, left: 0, bottom: 60 }}
          barGap={2}
        >
          <defs>
            <linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#f97316" stopOpacity={0.8} />
              <stop offset="100%" stopColor="#ef4444" stopOpacity={0.8} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          
          <XAxis 
            dataKey="name" 
            stroke="#475569" 
            fontSize={10} 
            tickLine={false}
            axisLine={false}
            angle={-45}
            textAnchor="end"
            interval={0}
            fontFamily="JetBrains Mono"
          />
          
          {/* Left Y-Axis: Raw Counts */}
          <YAxis 
            yAxisId="left"
            stroke="#475569" 
            fontSize={10} 
            tickLine={false} 
            axisLine={false}
            label={{ value: 'Invocations (Count)', angle: -90, position: 'insideLeft', fill: '#475569', fontSize: 10, offset: 10, fontWeight: 'bold' }}
          />
          
          {/* Right Y-Axis: Deviation Percentage */}
          <YAxis 
            yAxisId="right"
            orientation="right"
            stroke="#f97316" 
            fontSize={10} 
            tickLine={false} 
            axisLine={false}
            label={{ value: 'Variance (%)', angle: 90, position: 'insideRight', fill: '#f97316', fontSize: 10, offset: 10, fontWeight: 'bold' }}
          />

          <Tooltip content={<CustomTooltip />} cursor={{ fill: '#1e293b', opacity: 0.4 }} />
          
          <Legend 
            verticalAlign="top" 
            align="right" 
            wrapperStyle={{ paddingBottom: '30px', fontSize: '10px', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em' }}
          />
          
          <Bar 
            yAxisId="left"
            name="Baseline Ops" 
            dataKey="baseline" 
            fill="#334155" 
            radius={[2, 2, 0, 0]} 
            barSize={12}
          />
          
          <Bar 
            yAxisId="left"
            name="Test Capture" 
            dataKey="test" 
            radius={[2, 2, 0, 0]}
            barSize={12}
          >
            {data.map((entry, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={entry.deviation > 30 ? '#ef4444' : '#0ea5e9'} 
              />
            ))}
          </Bar>

          <Line
            yAxisId="right"
            type="monotone"
            name="Deviation Trend"
            dataKey="deviation"
            stroke="url(#lineGradient)"
            strokeWidth={3}
            dot={{ r: 3, fill: '#f97316', strokeWidth: 2, stroke: '#0f172a' }}
            activeDot={{ r: 5, fill: '#ef4444', strokeWidth: 0 }}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SyscallChart;
