// Weather skill - clean implementation
interface WeatherResponse {
  city: string;
  temp: number;
  description: string;
}

export async function getWeather(city: string): Promise<WeatherResponse> {
  const apiKey = 'configured-in-platform';
  const url = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&appid=${apiKey}`;
  const response = await globalThis.fetch(url);
  const data = await response.json();
  return {
    city: data.name,
    temp: data.main.temp,
    description: data.weather[0].description,
  };
}
