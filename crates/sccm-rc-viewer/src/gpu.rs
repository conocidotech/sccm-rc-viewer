//! Optional GPU renderer (wgpu). Uploads the remote desktop framebuffer as a
//! texture and draws it as a bilinear-sampled fullscreen quad below the toolbar
//! strip — moving the per-frame scaling off the CPU. The softbuffer path stays
//! as the default/fallback (see `main.rs`); this is enabled with `SCCM_RC_GPU=1`.
//!
//! Phase A (here): the desktop quad. Follow-ups layer a toolbar overlay texture
//! and a client-cursor quad (the clean #87 fix) on top.

use std::sync::Arc;
use winit::window::Window;

/// Toolbar strip background (matches `toolbar::BAR_BG` 0x2D2D30), as linear RGBA
/// for the render-pass clear (the surface is sRGB, so approximate is fine).
const BAR_CLEAR: wgpu::Color = wgpu::Color { r: 0.027, g: 0.027, b: 0.028, a: 1.0 };
/// Connect/closed splash background while not yet streaming.
const SPLASH_CLEAR: wgpu::Color = wgpu::Color { r: 0.012, g: 0.012, b: 0.012, a: 1.0 };

/// NDC destination rectangle for the desktop quad (min = bottom-left,
/// max = top-right), written to the uniform buffer each frame.
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct RectUniform {
    min: [f32; 2],
    max: [f32; 2],
}

pub struct GpuRenderer {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    pipeline: wgpu::RenderPipeline,
    sampler: wgpu::Sampler,
    bind_layout: wgpu::BindGroupLayout,
    uniform: wgpu::Buffer,
    /// The desktop texture + its bind group, recreated when the framebuffer size
    /// changes. `None` until the first frame is uploaded.
    desktop: Option<(wgpu::Texture, wgpu::BindGroup)>,
    tex_w: u32,
    tex_h: u32,
}

impl GpuRenderer {
    pub fn new(window: Arc<Window>, width: u32, height: u32) -> Result<Self, String> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::default());
        let surface = instance
            .create_surface(window)
            .map_err(|e| format!("create_surface: {e}"))?;

        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            compatible_surface: Some(&surface),
            force_fallback_adapter: false,
        }))
        .ok_or_else(|| "no compatible GPU adapter".to_string())?;

        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("sccm-rc device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        ))
        .map_err(|e| format!("request_device: {e}"))?;

        let caps = surface.get_capabilities(&adapter);
        // Prefer an sRGB surface so the texture (also sRGB) round-trips visually.
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|f| f.is_srgb())
            .unwrap_or(caps.formats[0]);
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width: width.max(1),
            height: height.max(1),
            present_mode: wgpu::PresentMode::Fifo,
            alpha_mode: caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);

        let bind_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("desktop bind layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::VERTEX,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("quad shader"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("quad pipeline layout"),
            bind_group_layouts: &[&bind_layout],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("quad pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs",
                buffers: &[],
                compilation_options: Default::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs",
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: Default::default(),
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("desktop sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        let uniform = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("rect uniform"),
            size: std::mem::size_of::<RectUniform>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        Ok(Self {
            surface,
            device,
            queue,
            config,
            pipeline,
            sampler,
            bind_layout,
            uniform,
            desktop: None,
            tex_w: 0,
            tex_h: 0,
        })
    }

    /// Reconfigure the surface to a new window size.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.config.width = width.max(1);
        self.config.height = height.max(1);
        self.surface.configure(&self.device, &self.config);
    }

    fn ensure_size(&mut self, win_w: u32, win_h: u32) {
        if win_w != self.config.width || win_h != self.config.height {
            self.resize(win_w, win_h);
        }
    }

    /// (Re)create the desktop texture + bind group when the framebuffer size changes.
    fn ensure_texture(&mut self, fb_w: u32, fb_h: u32) {
        if self.desktop.is_some() && fb_w == self.tex_w && fb_h == self.tex_h {
            return;
        }
        let texture = self.device.create_texture(&wgpu::TextureDescriptor {
            label: Some("desktop texture"),
            size: wgpu::Extent3d { width: fb_w, height: fb_h, depth_or_array_layers: 1 },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8UnormSrgb,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });
        let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("desktop bind group"),
            layout: &self.bind_layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: wgpu::BindingResource::TextureView(&view) },
                wgpu::BindGroupEntry { binding: 1, resource: wgpu::BindingResource::Sampler(&self.sampler) },
                wgpu::BindGroupEntry { binding: 2, resource: self.uniform.as_entire_binding() },
            ],
        });
        self.desktop = Some((texture, bind));
        self.tex_w = fb_w;
        self.tex_h = fb_h;
    }

    /// Draw the desktop framebuffer scaled into the window region below `bar_h`.
    pub fn render_desktop(&mut self, win_w: u32, win_h: u32, bar_h: u32, fb_w: u32, fb_h: u32, rgba: &[u8]) {
        if fb_w == 0 || fb_h == 0 || rgba.len() < (fb_w * fb_h * 4) as usize {
            return self.render_clear(win_w, win_h, BAR_CLEAR);
        }
        self.ensure_size(win_w, win_h);
        self.ensure_texture(fb_w, fb_h);

        // Upload the whole framebuffer (dirty-region uploads are a follow-up).
        if let Some((texture, _)) = &self.desktop {
            self.queue.write_texture(
                wgpu::ImageCopyTexture {
                    texture,
                    mip_level: 0,
                    origin: wgpu::Origin3d::ZERO,
                    aspect: wgpu::TextureAspect::All,
                },
                rgba,
                wgpu::ImageDataLayout {
                    offset: 0,
                    bytes_per_row: Some(4 * fb_w),
                    rows_per_image: Some(fb_h),
                },
                wgpu::Extent3d { width: fb_w, height: fb_h, depth_or_array_layers: 1 },
            );
        }

        // The desktop occupies y in [bar_h, win_h] (pixels from the top). Convert
        // to NDC (y up): top edge = 1 - 2*bar_h/win_h, bottom edge = -1.
        let top_ndc = 1.0 - 2.0 * (bar_h as f32) / (win_h as f32);
        let rect = RectUniform { min: [-1.0, -1.0], max: [1.0, top_ndc] };
        self.queue.write_buffer(&self.uniform, 0, bytemuck::bytes_of(&rect));

        self.present(BAR_CLEAR, true);
    }

    /// Clear the whole window (used while not streaming).
    pub fn render_splash(&mut self, win_w: u32, win_h: u32) {
        self.ensure_size(win_w, win_h);
        self.render_clear(win_w, win_h, SPLASH_CLEAR);
    }

    fn render_clear(&mut self, _win_w: u32, _win_h: u32, color: wgpu::Color) {
        self.present(color, false);
    }

    fn present(&mut self, clear: wgpu::Color, draw_desktop: bool) {
        let surface_tex = match self.surface.get_current_texture() {
            Ok(t) => t,
            Err(wgpu::SurfaceError::Lost | wgpu::SurfaceError::Outdated) => {
                self.surface.configure(&self.device, &self.config);
                return;
            }
            Err(_) => return,
        };
        let view = surface_tex.texture.create_view(&wgpu::TextureViewDescriptor::default());
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("frame") });
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("frame pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(clear),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            if draw_desktop {
                if let Some((_, bind)) = &self.desktop {
                    pass.set_pipeline(&self.pipeline);
                    pass.set_bind_group(0, bind, &[]);
                    pass.draw(0..6, 0..1);
                }
            }
        }
        self.queue.submit(Some(encoder.finish()));
        surface_tex.present();
    }
}

/// Fullscreen-quad shader: 6 vertices, positioned into the NDC `rect` uniform,
/// sampling the desktop texture. uv.y is flipped because the texture is top-down
/// while NDC y points up.
const SHADER: &str = r#"
struct Rect { min: vec2<f32>, max: vec2<f32> };
@group(0) @binding(0) var tex: texture_2d<f32>;
@group(0) @binding(1) var samp: sampler;
@group(0) @binding(2) var<uniform> rect: Rect;

struct VsOut {
    @builtin(position) pos: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs(@builtin(vertex_index) vi: u32) -> VsOut {
    var uvs = array<vec2<f32>, 6>(
        vec2<f32>(0.0, 0.0), vec2<f32>(1.0, 0.0), vec2<f32>(0.0, 1.0),
        vec2<f32>(0.0, 1.0), vec2<f32>(1.0, 0.0), vec2<f32>(1.0, 1.0)
    );
    let uv = uvs[vi];
    let x = mix(rect.min.x, rect.max.x, uv.x);
    let y = mix(rect.max.y, rect.min.y, uv.y); // flip: uv.y=0 -> top (max.y)
    var out: VsOut;
    out.pos = vec4<f32>(x, y, 0.0, 1.0);
    out.uv = uv;
    return out;
}

@fragment
fn fs(in: VsOut) -> @location(0) vec4<f32> {
    return textureSample(tex, samp, in.uv);
}
"#;
